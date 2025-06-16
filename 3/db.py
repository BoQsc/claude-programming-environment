# enhanced_safe_db_v2.py - Concurrency-safe with optimistic locking

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
from dataclasses import dataclass

logger = logging.getLogger(__name__)

class DatabaseError(Exception):
    """Custom database exception"""
    pass

class TransactionError(DatabaseError):
    """Transaction-specific exception"""
    pass

class ConcurrencyError(TransactionError):
    """Concurrency conflict exception"""
    pass

class TransactionState(Enum):
    ACTIVE = "active"
    COMMITTED = "committed"
    ABORTED = "aborted"

@dataclass
class VersionedValue:
    """Wrapper for values with version tracking"""
    value: Any
    version: int
    updated_at: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "version": self.version,
            "updated_at": self.updated_at
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VersionedValue':
        return cls(
            value=data.get("value"),
            version=data.get("version", 1),
            updated_at=data.get("updated_at", time.time())
        )

class Operation:
    """Represents a single database operation in a transaction"""
    
    def __init__(self, op_type: str, collection: str, key: str, 
                 old_value: Any = None, new_value: Any = None, 
                 old_version: int = None, new_version: int = None):
        self.op_type = op_type  # 'set', 'delete', 'update', 'increment'
        self.collection = collection
        self.key = key
        self.old_value = old_value
        self.new_value = new_value
        self.old_version = old_version
        self.new_version = new_version
        self.timestamp = time.time()

class SafeTransaction:
    """Enhanced transaction with optimistic locking"""
    
    def __init__(self, tx_id: str, db: 'EnhancedSafeDB'):
        self.tx_id = tx_id
        self.db = db
        self.state = TransactionState.ACTIVE
        self.operations: List[Operation] = []
        self.changes: Dict[str, Dict[str, VersionedValue]] = {}  # collection -> {key: versioned_value}
        self.read_versions: Dict[str, Dict[str, int]] = {}  # collection -> {key: version_when_read}
        self.created_at = time.time()
    
    async def get(self, collection_name: str, key: str) -> Optional[Any]:
        """Get value within transaction context"""
        if self.state != TransactionState.ACTIVE:
            raise TransactionError(f"Transaction {self.tx_id} is not active")
        
        # Check staged changes first
        if collection_name in self.changes and key in self.changes[collection_name]:
            staged_value = self.changes[collection_name][key]
            return None if staged_value.value == "___DELETED___" else staged_value.value
        
        # Get from actual collection
        collection = await self.db.get_collection(collection_name)
        versioned_value = await collection._get_versioned(key)
        
        if versioned_value is None:
            return None
        
        # Track the version we read for conflict detection
        if collection_name not in self.read_versions:
            self.read_versions[collection_name] = {}
        self.read_versions[collection_name][key] = versioned_value.version
        
        return versioned_value.value
    
    async def set(self, collection_name: str, key: str, value: Any):
        """Set value within transaction"""
        if self.state != TransactionState.ACTIVE:
            raise TransactionError(f"Transaction {self.tx_id} is not active")
        
        # Get current version if exists
        old_version = None
        old_value = None
        if collection_name in self.read_versions and key in self.read_versions[collection_name]:
            old_version = self.read_versions[collection_name][key]
        else:
            # Read current state to get version
            collection = await self.db.get_collection(collection_name)
            current = await collection._get_versioned(key)
            if current:
                old_version = current.version
                old_value = current.value
                # Track this read
                if collection_name not in self.read_versions:
                    self.read_versions[collection_name] = {}
                self.read_versions[collection_name][key] = old_version
        
        # Create new versioned value
        new_version = (old_version or 0) + 1
        versioned_value = VersionedValue(
            value=value,
            version=new_version,
            updated_at=time.time()
        )
        
        # Stage the change
        if collection_name not in self.changes:
            self.changes[collection_name] = {}
        self.changes[collection_name][key] = versioned_value
        
        # Log operation
        op = Operation('set', collection_name, key, old_value, value, old_version, new_version)
        self.operations.append(op)
    
    async def delete(self, collection_name: str, key: str) -> bool:
        """Delete value within transaction"""
        if self.state != TransactionState.ACTIVE:
            raise TransactionError(f"Transaction {self.tx_id} is not active")
        
        # Check if key exists
        current_value = await self.get(collection_name, key)
        if current_value is None:
            return False
        
        # Get current version
        old_version = self.read_versions[collection_name][key]
        new_version = old_version + 1
        
        # Create deletion marker
        versioned_value = VersionedValue(
            value="___DELETED___",
            version=new_version,
            updated_at=time.time()
        )
        
        if collection_name not in self.changes:
            self.changes[collection_name] = {}
        self.changes[collection_name][key] = versioned_value
        
        # Log operation
        op = Operation('delete', collection_name, key, current_value, None, old_version, new_version)
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
    
    async def commit(self):
        """Commit all changes with conflict detection"""
        if self.state != TransactionState.ACTIVE:
            raise TransactionError(f"Transaction {self.tx_id} is not active")
        
        try:
            # Check for conflicts before committing
            await self._check_conflicts()
            
            # Apply all changes atomically
            for collection_name, changes in self.changes.items():
                collection = await self.db.get_collection(collection_name)
                
                for key, versioned_value in changes.items():
                    if versioned_value.value == "___DELETED___":
                        await collection._delete_versioned(key, versioned_value.version)
                    else:
                        await collection._set_versioned(key, versioned_value)
            
            self.state = TransactionState.COMMITTED
            logger.info(f"✅ Transaction {self.tx_id} committed with {len(self.operations)} operations")
            
        except ConcurrencyError as e:
            await self.rollback()
            raise e
        except Exception as e:
            await self.rollback()
            raise TransactionError(f"Commit failed: {e}")
    
    async def _check_conflicts(self):
        """Check for version conflicts"""
        for collection_name, read_versions in self.read_versions.items():
            collection = await self.db.get_collection(collection_name)
            
            for key, expected_version in read_versions.items():
                # Skip if we're going to modify this key anyway
                if (collection_name in self.changes and 
                    key in self.changes[collection_name]):
                    continue
                
                current = await collection._get_versioned(key)
                current_version = current.version if current else 0
                
                if current_version != expected_version:
                    raise ConcurrencyError(
                        f"Conflict detected on {collection_name}.{key}: "
                        f"expected version {expected_version}, found {current_version}"
                    )
    
    async def rollback(self):
        """Rollback the transaction"""
        if self.state == TransactionState.ABORTED:
            return
        
        self.state = TransactionState.ABORTED
        self.changes.clear()
        self.read_versions.clear()
        logger.info(f"🔄 Transaction {self.tx_id} rolled back")
    
    def get_info(self) -> Dict[str, Any]:
        """Get transaction information"""
        return {
            "id": self.tx_id,
            "state": self.state.value,
            "operations": len(self.operations),
            "collections": list(self.changes.keys()),
            "reads": {coll: list(keys.keys()) for coll, keys in self.read_versions.items()},
            "age_seconds": time.time() - self.created_at,
            "operation_details": [
                {
                    "type": op.op_type,
                    "collection": op.collection,
                    "key": op.key,
                    "old_version": op.old_version,
                    "new_version": op.new_version,
                    "timestamp": op.timestamp
                } for op in self.operations
            ]
        }

class EnhancedCollection:
    """Enhanced collection with versioning and concurrency control"""
    
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
    
    async def _read_data(self) -> Dict[str, Dict[str, Any]]:
        """Read versioned data with caching"""
        current_time = time.time()
        
        # Return cached data if still valid
        if (self._data_cache is not None and 
            current_time - self._cache_time < self.cache_ttl):
            return self._data_cache.copy()
        
        # Read from file
        try:
            with open(self.file_path, 'r') as f:
                raw_data = json.load(f)
            
            # Convert to versioned format if needed
            versioned_data = {}
            for key, value in raw_data.items():
                if isinstance(value, dict) and "version" in value and "updated_at" in value:
                    # Already versioned
                    versioned_data[key] = value
                else:
                    # Legacy data, add version info
                    versioned_data[key] = {
                        "value": value,
                        "version": 1,
                        "updated_at": time.time()
                    }
            
            # Update cache
            self._data_cache = versioned_data.copy()
            self._cache_time = current_time
            
            return versioned_data
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
    
    async def _write_data(self, data: Dict[str, Dict[str, Any]], max_retries: int = 3):
        """Write versioned data with retry mechanism"""
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
    
    async def _get_versioned(self, key: str) -> Optional[VersionedValue]:
        """Get versioned value by key"""
        data = await self._read_data()
        raw_value = data.get(key)
        if raw_value is None:
            return None
        return VersionedValue.from_dict(raw_value)
    
    async def _set_versioned(self, key: str, versioned_value: VersionedValue):
        """Set versioned value by key"""
        data = await self._read_data()
        data[key] = versioned_value.to_dict()
        await self._write_data(data)
    
    async def _delete_versioned(self, key: str, expected_version: int) -> bool:
        """Delete versioned value with version check"""
        data = await self._read_data()
        if key in data:
            current_version = data[key].get("version", 1)
            if current_version != expected_version:
                raise ConcurrencyError(f"Version mismatch during delete: expected {expected_version}, found {current_version}")
            del data[key]
            await self._write_data(data)
            return True
        return False
    
    # Public API (backwards compatible)
    async def get(self, key: str) -> Optional[Any]:
        """Get value by key"""
        versioned = await self._get_versioned(key)
        return versioned.value if versioned else None
    
    async def set(self, key: str, value: Any) -> bool:
        """Set value by key"""
        # Get current version or start at 1
        current = await self._get_versioned(key)
        new_version = (current.version if current else 0) + 1
        
        versioned_value = VersionedValue(
            value=value,
            version=new_version,
            updated_at=time.time()
        )
        
        await self._set_versioned(key, versioned_value)
        return True
    
    async def delete(self, key: str) -> bool:
        """Delete value by key"""
        current = await self._get_versioned(key)
        if current:
            await self._delete_versioned(key, current.version)
            return True
        return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists"""
        versioned = await self._get_versioned(key)
        return versioned is not None
    
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
        return [VersionedValue.from_dict(v).value for v in data.values()]
    
    async def items(self) -> List[tuple]:
        """Get all key-value pairs"""
        data = await self._read_data()
        return [(k, VersionedValue.from_dict(v).value) for k, v in data.items()]
    
    async def clear(self) -> bool:
        """Clear all data"""
        await self._write_data({})
        return True
    
    async def find(self, filter_func: Optional[Callable] = None, 
                   limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Find items with optional filter function"""
        data = await self._read_data()
        
        results = []
        for key, versioned_data in data.items():
            value = VersionedValue.from_dict(versioned_data).value
            
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

# Rest of the classes remain the same...
class EnhancedSafeDB:
    """Enhanced database with optimistic locking"""
    
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
    async def transaction(self, max_retries: int = 3):
        """Create transaction context manager with automatic retry on conflicts"""
        for attempt in range(max_retries):
            self.tx_counter += 1
            tx_id = f"tx_{self.tx_counter}_{int(time.time() * 1000) % 10000}"
            
            transaction = SafeTransaction(tx_id, self)
            self._active_transactions[tx_id] = transaction
            
            try:
                yield transaction
                # Auto-commit if no exception
                if transaction.state == TransactionState.ACTIVE:
                    await transaction.commit()
                break  # Success, exit retry loop
                
            except ConcurrencyError as e:
                if transaction.state == TransactionState.ACTIVE:
                    await transaction.rollback()
                
                if attempt < max_retries - 1:
                    logger.info(f"🔄 Retrying transaction due to conflict (attempt {attempt + 1}/{max_retries})")
                    await asyncio.sleep(0.01 * (2 ** attempt))  # Exponential backoff
                    continue
                else:
                    logger.error(f"❌ Transaction failed after {max_retries} attempts: {e}")
                    raise
                    
            except Exception as e:
                # Auto-rollback on exception
                if transaction.state == TransactionState.ACTIVE:
                    await transaction.rollback()
                raise
            finally:
                # Cleanup
                if tx_id in self._active_transactions:
                    del self._active_transactions[tx_id]
    
    # ... rest of the methods remain the same
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
                "version": "enhanced_safe_db_v2.0"
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
            try:
                collection = await self.get_collection(collection_name)
                stats["collections"][collection_name] = {
                    "count": await collection.count(),
                    "file_size": collection.file_path.stat().st_size if collection.file_path.exists() else 0
                }
            except Exception as e:
                logger.error(f"Error getting stats for collection {collection_name}: {e}")
                stats["collections"][collection_name] = {
                    "count": 0,
                    "file_size": 0,
                    "error": str(e)
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

# Factory function
def create_database(db_path: str = './enhanced_data', cache_ttl: float = 1.0) -> EnhancedSafeDB:
    """Factory function to create a database instance"""
    return EnhancedSafeDB(db_path, cache_ttl)