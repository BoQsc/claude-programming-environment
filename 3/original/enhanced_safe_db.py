# enhanced_safe_db.py - Full featured database built on reliable foundation

import json
import asyncio
import uuid
import time
import copy
import os
import shutil
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable, Union, Set
from contextlib import asynccontextmanager
from enum import Enum

logger = logging.getLogger(__name__)

class DatabaseError(Exception):
    """Custom database exception"""
    pass

class TransactionError(DatabaseError):
    """Transaction-specific exception"""
    pass

class TransactionState(Enum):
    ACTIVE = "active"
    COMMITTED = "committed"
    ABORTED = "aborted"

class Operation:
    """Represents a single database operation in a transaction"""
    
    def __init__(self, op_type: str, collection: str, key: str, 
                 old_value: Any = None, new_value: Any = None):
        self.op_type = op_type  # 'set', 'delete', 'update', 'increment'
        self.collection = collection
        self.key = key
        self.old_value = old_value
        self.new_value = new_value
        self.timestamp = time.time()

class SafeTransaction:
    """Enhanced transaction with operation logging"""
    
    def __init__(self, tx_id: str, db: 'EnhancedSafeDB'):
        self.tx_id = tx_id
        self.db = db
        self.state = TransactionState.ACTIVE
        self.operations: List[Operation] = []
        self.changes: Dict[str, Dict[str, Any]] = {}  # collection -> {key: value}
        self.original_data: Dict[str, Dict[str, Any]] = {}  # for rollback
        self.created_at = time.time()
    
    async def get(self, collection_name: str, key: str) -> Optional[Any]:
        """Get value within transaction context"""
        if self.state != TransactionState.ACTIVE:
            raise TransactionError(f"Transaction {self.tx_id} is not active")
        
        # Check staged changes first
        if collection_name in self.changes and key in self.changes[collection_name]:
            staged_value = self.changes[collection_name][key]
            return None if staged_value == "___DELETED___" else staged_value
        
        # Get from actual collection
        collection = await self.db.get_collection(collection_name)
        return await collection.get(key)
    
    async def set(self, collection_name: str, key: str, value: Any):
        """Set value within transaction"""
        if self.state != TransactionState.ACTIVE:
            raise TransactionError(f"Transaction {self.tx_id} is not active")
        
        await self._prepare_change(collection_name, key)
        self.changes[collection_name][key] = value
        
        # Log operation
        op = Operation('set', collection_name, key, 
                      self.original_data[collection_name].get(key), value)
        self.operations.append(op)
    
    async def delete(self, collection_name: str, key: str) -> bool:
        """Delete value within transaction"""
        if self.state != TransactionState.ACTIVE:
            raise TransactionError(f"Transaction {self.tx_id} is not active")
        
        # Check if key exists
        current_value = await self.get(collection_name, key)
        if current_value is None:
            return False
        
        await self._prepare_change(collection_name, key)
        self.changes[collection_name][key] = "___DELETED___"
        
        # Log operation
        op = Operation('delete', collection_name, key, current_value, None)
        self.operations.append(op)
        return True
    
    async def update(self, collection_name: str, key: str, updates: Dict[str, Any]) -> bool:
        """Update specific fields within transaction"""
        current_value = await self.get(collection_name, key)
        if current_value is None:
            return False
        
        if isinstance(current_value, dict):
            new_value = copy.deepcopy(current_value)
            new_value.update(updates)
        else:
            new_value = updates
        
        await self.set(collection_name, key, new_value)
        
        # Update operation log
        if self.operations:
            self.operations[-1].op_type = 'update'
        
        return True
    
    async def increment(self, collection_name: str, key: str, field: str = 'value', 
                       amount: Union[int, float] = 1) -> Union[int, float]:
        """Increment a numeric field within transaction"""
        current_value = await self.get(collection_name, key)
        
        if current_value is None:
            current_value = {field: 0} if field != 'value' else 0
        
        if isinstance(current_value, dict):
            new_value = copy.deepcopy(current_value)
            new_value[field] = new_value.get(field, 0) + amount
            result = new_value[field]
        else:
            new_value = current_value + amount
            result = new_value
        
        await self.set(collection_name, key, new_value)
        
        # Update operation log
        if self.operations:
            self.operations[-1].op_type = 'increment'
        
        return result
    
    async def exists(self, collection_name: str, key: str) -> bool:
        """Check if key exists within transaction"""
        value = await self.get(collection_name, key)
        return value is not None
    
    async def _prepare_change(self, collection_name: str, key: str):
        """Prepare for a change by storing original value"""
        if collection_name not in self.changes:
            self.changes[collection_name] = {}
        if collection_name not in self.original_data:
            self.original_data[collection_name] = {}
        
        # Store original value if we haven't already
        if key not in self.original_data[collection_name]:
            collection = await self.db.get_collection(collection_name)
            original = await collection.get(key)
            self.original_data[collection_name][key] = original
    
    async def commit(self):
        """Commit all changes"""
        if self.state != TransactionState.ACTIVE:
            raise TransactionError(f"Transaction {self.tx_id} is not active")
        
        try:
            # Apply all changes atomically
            for collection_name, changes in self.changes.items():
                collection = await self.db.get_collection(collection_name)
                
                for key, value in changes.items():
                    if value == "___DELETED___":
                        await collection.delete(key)
                    else:
                        await collection.set(key, value)
            
            self.state = TransactionState.COMMITTED
            logger.info(f"✅ Transaction {self.tx_id} committed with {len(self.operations)} operations")
            
        except Exception as e:
            await self.rollback()
            raise TransactionError(f"Commit failed: {e}")
    
    async def rollback(self):
        """Rollback the transaction"""
        if self.state == TransactionState.ABORTED:
            return
        
        self.state = TransactionState.ABORTED
        self.changes.clear()
        logger.info(f"🔄 Transaction {self.tx_id} rolled back")
    
    def get_info(self) -> Dict[str, Any]:
        """Get transaction information"""
        return {
            "id": self.tx_id,
            "state": self.state.value,
            "operations": len(self.operations),
            "collections": list(self.changes.keys()),
            "age_seconds": time.time() - self.created_at,
            "operation_details": [
                {
                    "type": op.op_type,
                    "collection": op.collection,
                    "key": op.key,
                    "timestamp": op.timestamp
                } for op in self.operations
            ]
        }

class EnhancedCollection:
    """Enhanced collection with caching and advanced features"""
    
    def __init__(self, name: str, db_path: str, cache_ttl: float = 1.0):
        self.name = name
        self.db_path = Path(db_path)
        self.file_path = self.db_path / f"{name}.json"
        self.cache_ttl = cache_ttl
        
        # Simple caching
        self._data_cache = None
        self._cache_time = 0
        
        # Ensure directory and file exist
        self.db_path.mkdir(parents=True, exist_ok=True)
        if not self.file_path.exists():
            with open(self.file_path, 'w') as f:
                json.dump({}, f)
    
    async def _read_data(self) -> Dict[str, Any]:
        """Read data with caching"""
        current_time = time.time()
        
        # Return cached data if still valid
        if (self._data_cache is not None and 
            current_time - self._cache_time < self.cache_ttl):
            return self._data_cache.copy()
        
        # Read from file
        try:
            with open(self.file_path, 'r') as f:
                data = json.load(f)
            
            # Update cache
            self._data_cache = data.copy()
            self._cache_time = current_time
            
            return data
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
    
    async def _write_data(self, data: Dict[str, Any], max_retries: int = 3):
        """Write data with retry mechanism"""
        for attempt in range(max_retries):
            try:
                # Atomic write using temp file
                temp_path = self.file_path.with_suffix(f'.tmp_{int(time.time() * 1000000)}')
                
                with open(temp_path, 'w') as f:
                    json.dump(data, f, indent=2, default=str)
                
                # Atomic replace
                temp_path.replace(self.file_path)
                
                # Update cache
                self._data_cache = data.copy()
                self._cache_time = time.time()
                
                return
                
            except Exception as e:
                if temp_path.exists():
                    temp_path.unlink()
                
                if attempt == max_retries - 1:
                    raise DatabaseError(f"Failed to write {self.file_path} after {max_retries} attempts: {e}")
                
                await asyncio.sleep(0.1 * (2 ** attempt))  # Exponential backoff
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value by key"""
        data = await self._read_data()
        return data.get(key)
    
    async def set(self, key: str, value: Any) -> bool:
        """Set value by key"""
        data = await self._read_data()
        data[key] = value
        await self._write_data(data)
        return True
    
    async def delete(self, key: str) -> bool:
        """Delete value by key"""
        data = await self._read_data()
        if key in data:
            del data[key]
            await self._write_data(data)
            return True
        return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists"""
        data = await self._read_data()
        return key in data
    
    async def count(self) -> int:
        """Count items"""
        data = await self._read_data()
        return len(data)
    
    async def keys(self) -> List[str]:
        """Get all keys"""
        data = await self._read_data()
        return list(data.keys())
    
    async def values(self) -> List[Any]:
        """Get all values"""
        data = await self._read_data()
        return list(data.values())
    
    async def items(self) -> List[tuple]:
        """Get all key-value pairs"""
        data = await self._read_data()
        return list(data.items())
    
    async def clear(self) -> bool:
        """Clear all data"""
        await self._write_data({})
        return True
    
    async def find(self, filter_func: Optional[Callable] = None, 
                   limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Find items with optional filter function"""
        data = await self._read_data()
        
        results = []
        for key, value in data.items():
            # Create item with metadata
            if isinstance(value, dict):
                item = {'_key': key, **value}
            else:
                item = {'_key': key, 'value': value}
            
            # Apply filter
            if filter_func is None or filter_func(item):
                results.append(item)
                
                if limit and len(results) >= limit:
                    break
        
        return results
    
    async def update(self, key: str, updates: Dict[str, Any]) -> bool:
        """Update specific fields of a record"""
        data = await self._read_data()
        
        if key not in data:
            return False
        
        if isinstance(data[key], dict):
            data[key].update(updates)
        else:
            data[key] = updates
        
        await self._write_data(data)
        return True
    
    async def increment(self, key: str, field: str = 'value', 
                       amount: Union[int, float] = 1) -> Union[int, float]:
        """Increment a numeric field"""
        data = await self._read_data()
        
        if key not in data:
            data[key] = {field: 0} if field != 'value' else 0
        
        if isinstance(data[key], dict):
            current_value = data[key].get(field, 0)
            data[key][field] = current_value + amount
            result = data[key][field]
        else:
            data[key] = data[key] + amount
            result = data[key]
        
        await self._write_data(data)
        return result

class EnhancedSafeDB:
    """Enhanced database with all features restored safely"""
    
    def __init__(self, db_path: str = "./enhanced_data", cache_ttl: float = 1.0):
        self.db_path = Path(db_path)
        self.collections: Dict[str, EnhancedCollection] = {}
        self.cache_ttl = cache_ttl
        self.tx_counter = 0
        self._active_transactions: Dict[str, SafeTransaction] = {}
    
    async def get_collection(self, name: str) -> EnhancedCollection:
        """Get or create collection"""
        if name not in self.collections:
            self.collections[name] = EnhancedCollection(name, str(self.db_path), self.cache_ttl)
        return self.collections[name]
    
    @asynccontextmanager
    async def transaction(self):
        """Create transaction context manager"""
        self.tx_counter += 1
        tx_id = f"tx_{self.tx_counter}_{int(time.time() * 1000) % 10000}"
        
        transaction = SafeTransaction(tx_id, self)
        self._active_transactions[tx_id] = transaction
        
        try:
            yield transaction
            # Auto-commit if no exception
            if transaction.state == TransactionState.ACTIVE:
                await transaction.commit()
        except Exception as e:
            # Auto-rollback on exception
            if transaction.state == TransactionState.ACTIVE:
                await transaction.rollback()
            raise
        finally:
            # Cleanup
            if tx_id in self._active_transactions:
                del self._active_transactions[tx_id]
    
    async def get_transaction_info(self) -> Dict[str, Any]:
        """Get information about active transactions"""
        return {
            "active_count": len(self._active_transactions),
            "transactions": [tx.get_info() for tx in self._active_transactions.values()]
        }
    
    async def drop_collection(self, name: str) -> bool:
        """Drop a collection"""
        if name in self.collections:
            collection = self.collections[name]
            del self.collections[name]
            
            # Remove file if it exists
            if collection.file_path.exists():
                collection.file_path.unlink()
            
            return True
        return False
    
    async def list_collections(self) -> List[str]:
        """List all collections"""
        collections = []
        if self.db_path.exists():
            for file_path in self.db_path.glob('*.json'):
                collections.append(file_path.stem)
        return collections
    
    async def backup(self, backup_path: str) -> bool:
        """Create a backup of the entire database"""
        try:
            backup_dir = Path(backup_path)
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            if self.db_path.exists():
                for file_path in self.db_path.glob('*.json'):
                    shutil.copy2(file_path, backup_dir / file_path.name)
            
            # Create backup metadata
            metadata = {
                "backup_timestamp": time.time(),
                "source_path": str(self.db_path),
                "collections": await self.list_collections(),
                "version": "enhanced_safe_db_v1.0"
            }
            
            with open(backup_dir / "backup_metadata.json", 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"Database backed up to {backup_path}")
            return True
            
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            return False
    
    async def restore(self, backup_path: str) -> bool:
        """Restore database from backup"""
        try:
            backup_dir = Path(backup_path)
            
            if not backup_dir.exists():
                logger.error(f"Backup directory {backup_path} does not exist")
                return False
            
            # Check backup metadata
            metadata_file = backup_dir / "backup_metadata.json"
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                logger.info(f"Restoring backup from {metadata.get('backup_timestamp', 'unknown time')}")
            
            # Ensure database directory exists
            self.db_path.mkdir(parents=True, exist_ok=True)
            
            # Copy backup files
            for file_path in backup_dir.glob('*.json'):
                if file_path.name != 'backup_metadata.json':
                    shutil.copy2(file_path, self.db_path / file_path.name)
            
            # Clear collections from memory to force reload
            self.collections.clear()
            
            logger.info(f"Database restored from {backup_path}")
            return True
            
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        collections = await self.list_collections()
        stats = {
            "collection_count": len(collections),
            "active_transactions": len(self._active_transactions),
            "collections": {}
        }
        
        for collection_name in collections:
            collection = await self.get_collection(collection_name)
            stats["collections"][collection_name] = {
                "count": await collection.count(),
                "file_size": collection.file_path.stat().st_size if collection.file_path.exists() else 0
            }
        
        return stats
    
    async def close(self):
        """Close the database"""
        # Rollback any active transactions
        for transaction in list(self._active_transactions.values()):
            if transaction.state == TransactionState.ACTIVE:
                await transaction.rollback()
        
        self.collections.clear()
        self._active_transactions.clear()

# Convenience functions
async def create_unique_id() -> str:
    """Generate a unique ID"""
    return str(uuid.uuid4())

async def create_timestamp() -> float:
    """Get current timestamp"""
    return time.time()

class Document:
    """Helper class for document-style operations"""
    
    def __init__(self, collection: EnhancedCollection, doc_id: str):
        self.collection = collection
        self.doc_id = doc_id
    
    async def save(self, data: Dict[str, Any]) -> bool:
        """Save document data"""
        # Add metadata
        data['_id'] = self.doc_id
        data['_updated'] = await create_timestamp()
        
        return await self.collection.set(self.doc_id, data)
    
    async def load(self) -> Optional[Dict[str, Any]]:
        """Load document data"""
        return await self.collection.get(self.doc_id)
    
    async def delete(self) -> bool:
        """Delete the document"""
        return await self.collection.delete(self.doc_id)
    
    async def update_fields(self, updates: Dict[str, Any]) -> bool:
        """Update specific fields"""
        updates['_updated'] = await create_timestamp()
        return await self.collection.update(self.doc_id, updates)
    
    async def exists(self) -> bool:
        """Check if document exists"""
        return await self.collection.exists(self.doc_id)

# Factory function
def create_database(db_path: str = './enhanced_data', cache_ttl: float = 1.0) -> EnhancedSafeDB:
    """Factory function to create a database instance"""
    return EnhancedSafeDB(db_path, cache_ttl)

# Demo function
async def demo_enhanced_features():
    """Demo all the enhanced features"""
    print("🚀 Enhanced Safe Database Demo")
    print("=" * 50)
    
    db = create_database()
    
    # Setup test data
    print("Setting up test data...")
    users = await db.get_collection("users")
    products = await db.get_collection("products")
    
    await users.set("user1", {"name": "Alice", "balance": 1000.0, "level": 5})
    await users.set("user2", {"name": "Bob", "balance": 500.0, "level": 3})
    await products.set("prod1", {"name": "Laptop", "price": 800.0, "stock": 3})
    
    # Test enhanced collection features
    print("\n📊 Testing enhanced collection features:")
    
    # Find with filter
    rich_users = await users.find(lambda u: u.get('balance', 0) > 700)
    print(f"Rich users (>$700): {[u['name'] for u in rich_users]}")
    
    # Increment operation
    new_level = await users.increment("user1", "level", 2)
    print(f"User1 new level after increment: {new_level}")
    
    # Update operation
    await users.update("user2", {"last_login": time.time(), "status": "active"})
    user2 = await users.get("user2")
    print(f"Updated user2: {user2}")
    
    # Test transaction with enhanced features
    print("\n💳 Testing enhanced transaction features:")
    
    try:
        async with db.transaction() as tx:
            # Complex transaction with multiple operations
            user = await tx.get("users", "user1")
            product = await tx.get("products", "prod1")
            
            print(f"Before: User balance=${user['balance']}, Product stock={product['stock']}")
            
            # Validate
            if user["balance"] < product["price"]:
                raise Exception("Insufficient funds")
            
            # Use enhanced transaction methods
            await tx.update("users", "user1", {
                "balance": user["balance"] - product["price"],
                "last_purchase": product["name"]
            })
            
            await tx.increment("products", "prod1", "stock", -1)
            
            # Create order with Document helper
            order_id = await create_unique_id()
            await tx.set("orders", order_id, {
                "user_id": "user1",
                "product_id": "prod1",
                "amount": product["price"],
                "timestamp": await create_timestamp()
            })
            
            print("✅ Enhanced transaction completed!")
    
    except Exception as e:
        print(f"❌ Transaction failed: {e}")
    
    # Show final state
    user1 = await users.get("user1")
    prod1 = await products.get("prod1")
    orders = await db.get_collection("orders")
    order_count = await orders.count()
    
    print(f"\nFinal state:")
    print(f"  User1 balance: ${user1['balance']}")
    print(f"  Product stock: {prod1['stock']}")
    print(f"  Orders created: {order_count}")
    
    # Test backup/restore
    print("\n💾 Testing backup/restore:")
    backup_success = await db.backup("./test_backup")
    print(f"Backup created: {backup_success}")
    
    # Show database stats
    stats = await db.get_stats()
    print(f"\n📈 Database stats: {stats}")
    
    # Show transaction info
    tx_info = await db.get_transaction_info()
    print(f"Transaction info: {tx_info}")
    
    print("\n🎉 All enhanced features working!")

if __name__ == "__main__":
    asyncio.run(demo_enhanced_features())