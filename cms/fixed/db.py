import json
import asyncio
import os
import time
import uuid
import threading
import platform
from typing import Dict, Any, List, Optional, Union, Callable
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class DatabaseError(Exception):
    """Custom database exception"""
    pass


class Collection:
    """Represents a collection (table) in the database"""
    
    def __init__(self, name: str, db_path: str):
        self.name = name
        self.db_path = Path(db_path)
        self.file_path = self.db_path / f"{name}.json"
        self._lock = asyncio.Lock()
        self._data_cache = None
        self._cache_time = 0
        self._cache_ttl = 1.0  # Cache TTL in seconds
        self._is_windows = platform.system() == 'Windows'
    
    async def _ensure_file_exists(self):
        """Ensure the collection file exists"""
        if not self.file_path.exists():
            self.db_path.mkdir(parents=True, exist_ok=True)
            await self._write_file_async('{}')
    
    async def _read_file_async(self) -> str:
        """Read file content asynchronously using thread pool"""
        loop = asyncio.get_event_loop()
        
        def _read_file():
            try:
                with open(self.file_path, 'r', encoding='utf-8') as f:
                    return f.read()
            except FileNotFoundError:
                return '{}'
        
        return await loop.run_in_executor(None, _read_file)
    
    async def _write_file_async(self, content: str):
        """Write file content asynchronously using thread pool with Windows compatibility"""
        loop = asyncio.get_event_loop()
        
        def _write_file():
            max_retries = 3
            retry_delay = 0.1
            
            for attempt in range(max_retries):
                temp_file = None
                try:
                    # Create temporary file with unique suffix
                    temp_suffix = f".tmp_{int(time.time() * 1000000)}"
                    temp_file = self.file_path.with_suffix(temp_suffix)
                    
                    # Write to temporary file
                    with open(temp_file, 'w', encoding='utf-8') as f:
                        f.write(content)
                        f.flush()
                        os.fsync(f.fileno())  # Force write to disk
                    
                    # Windows-compatible file replacement
                    if self._is_windows:
                        # On Windows, we need to handle file replacement more carefully
                        if self.file_path.exists():
                            # Create backup
                            backup_file = self.file_path.with_suffix('.bak')
                            try:
                                if backup_file.exists():
                                    backup_file.unlink()
                                
                                # Move original to backup
                                self.file_path.rename(backup_file)
                                
                                # Move temp to original
                                temp_file.rename(self.file_path)
                                
                                # Remove backup
                                if backup_file.exists():
                                    backup_file.unlink()
                                
                            except Exception as e:
                                # Restore from backup if possible
                                if backup_file.exists() and not self.file_path.exists():
                                    backup_file.rename(self.file_path)
                                raise e
                        else:
                            # File doesn't exist, simple rename
                            temp_file.rename(self.file_path)
                    else:
                        # Unix-like systems can use atomic replace
                        temp_file.replace(self.file_path)
                    
                    return  # Success!
                    
                except (PermissionError, OSError) as e:
                    logger.warning(f"Write attempt {attempt + 1} failed: {e}")
                    
                    # Clean up temp file if it exists
                    if temp_file and temp_file.exists():
                        try:
                            temp_file.unlink()
                        except:
                            pass
                    
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                        retry_delay *= 2  # Exponential backoff
                    else:
                        raise
                        
                except Exception as e:
                    # Clean up temp file if it exists
                    if temp_file and temp_file.exists():
                        try:
                            temp_file.unlink()
                        except:
                            pass
                    raise
        
        await loop.run_in_executor(None, _write_file)
    
    async def _read_data(self) -> Dict[str, Any]:
        """Read data from file with caching"""
        current_time = time.time()
        
        # Return cached data if still valid
        if (self._data_cache is not None and 
            current_time - self._cache_time < self._cache_ttl):
            return self._data_cache.copy()
        
        await self._ensure_file_exists()
        
        try:
            content = await self._read_file_async()
            data = json.loads(content) if content.strip() else {}
            
            # Update cache
            self._data_cache = data.copy()
            self._cache_time = current_time
            
            return data
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error in {self.file_path}: {e}")
            raise DatabaseError(f"Corrupted data in collection {self.name}")
        except Exception as e:
            logger.error(f"Error reading {self.file_path}: {e}")
            raise DatabaseError(f"Failed to read collection {self.name}")
    
    async def _write_data(self, data: Dict[str, Any]):
        """Write data to file atomically"""
        try:
            content = json.dumps(data, indent=2, default=str)
            await self._write_file_async(content)
            
            # Update cache
            self._data_cache = data.copy()
            self._cache_time = time.time()
            
        except Exception as e:
            logger.error(f"Error writing to {self.file_path}: {e}")
            raise DatabaseError(f"Failed to write to collection {self.name}")
    
    async def get(self, key: str) -> Optional[Any]:
        """Get a value by key"""
        async with self._lock:
            data = await self._read_data()
            return data.get(key)
    
    async def set(self, key: str, value: Any) -> bool:
        """Set a value by key"""
        async with self._lock:
            data = await self._read_data()
            data[key] = value
            await self._write_data(data)
            return True
    
    async def delete(self, key: str) -> bool:
        """Delete a value by key"""
        async with self._lock:
            data = await self._read_data()
            if key in data:
                del data[key]
                await self._write_data(data)
                return True
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if a key exists"""
        async with self._lock:
            data = await self._read_data()
            return key in data
    
    async def keys(self) -> List[str]:
        """Get all keys"""
        async with self._lock:
            data = await self._read_data()
            return list(data.keys())
    
    async def values(self) -> List[Any]:
        """Get all values"""
        async with self._lock:
            data = await self._read_data()
            return list(data.values())
    
    async def items(self) -> List[tuple]:
        """Get all key-value pairs"""
        async with self._lock:
            data = await self._read_data()
            return list(data.items())
    
    async def clear(self) -> bool:
        """Clear all data"""
        async with self._lock:
            await self._write_data({})
            return True
    
    async def count(self) -> int:
        """Get count of items"""
        async with self._lock:
            data = await self._read_data()
            return len(data)
    
    async def find(self, filter_func: Optional[Callable] = None, 
                   limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Find items with optional filter function"""
        async with self._lock:
            data = await self._read_data()
            
            results = []
            for key, value in data.items():
                item = {'_key': key, **value} if isinstance(value, dict) else {'_key': key, 'value': value}
                
                if filter_func is None or filter_func(item):
                    results.append(item)
                    
                    if limit and len(results) >= limit:
                        break
            
            return results
    
    async def update(self, key: str, updates: Dict[str, Any]) -> bool:
        """Update specific fields of a record"""
        async with self._lock:
            data = await self._read_data()
            
            if key not in data:
                return False
            
            if isinstance(data[key], dict):
                data[key].update(updates)
            else:
                # If the value is not a dict, replace it with updates
                data[key] = updates
            
            await self._write_data(data)
            return True
    
    async def increment(self, key: str, field: str = 'value', amount: Union[int, float] = 1) -> Union[int, float]:
        """Increment a numeric field"""
        async with self._lock:
            data = await self._read_data()
            
            if key not in data:
                data[key] = {field: 0} if field != 'value' else 0
            
            if isinstance(data[key], dict):
                current_value = data[key].get(field, 0)
                data[key][field] = current_value + amount
                result = data[key][field]
            else:
                # Direct numeric value
                data[key] = data[key] + amount
                result = data[key]
            
            await self._write_data(data)
            return result


class AsyncJSONDB:
    """Asynchronous JSON Database with concurrent access support"""
    
    def __init__(self, db_path: str = './data'):
        self.db_path = Path(db_path)
        self.collections: Dict[str, Collection] = {}
        self._global_lock = asyncio.Lock()
    
    async def get_collection(self, name: str) -> Collection:
        """Get or create a collection"""
        if name not in self.collections:
            async with self._global_lock:
                # Double-check locking pattern
                if name not in self.collections:
                    self.collections[name] = Collection(name, str(self.db_path))
        
        return self.collections[name]
    
    async def drop_collection(self, name: str) -> bool:
        """Drop a collection"""
        async with self._global_lock:
            if name in self.collections:
                collection = self.collections[name]
                
                # Remove from memory
                del self.collections[name]
                
                # Remove file if it exists
                if collection.file_path.exists():
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, collection.file_path.unlink)
                
                return True
            return False
    
    async def list_collections(self) -> List[str]:
        """List all collections"""
        loop = asyncio.get_event_loop()
        
        def _list_files():
            collections = []
            if self.db_path.exists():
                for file_path in self.db_path.glob('*.json'):
                    collections.append(file_path.stem)
            return collections
        
        return await loop.run_in_executor(None, _list_files)
    
    async def backup(self, backup_path: str) -> bool:
        """Create a backup of the entire database"""
        import shutil
        
        loop = asyncio.get_event_loop()
        
        def _backup():
            try:
                backup_dir = Path(backup_path)
                backup_dir.mkdir(parents=True, exist_ok=True)
                
                if self.db_path.exists():
                    for file_path in self.db_path.glob('*.json'):
                        shutil.copy2(file_path, backup_dir / file_path.name)
                
                logger.info(f"Database backed up to {backup_path}")
                return True
            except Exception as e:
                logger.error(f"Backup failed: {e}")
                return False
        
        return await loop.run_in_executor(None, _backup)
    
    async def restore(self, backup_path: str) -> bool:
        """Restore database from backup"""
        import shutil
        
        loop = asyncio.get_event_loop()
        
        def _restore():
            try:
                backup_dir = Path(backup_path)
                
                if not backup_dir.exists():
                    logger.error(f"Backup directory {backup_path} does not exist")
                    return False
                
                # Ensure database directory exists
                self.db_path.mkdir(parents=True, exist_ok=True)
                
                # Copy backup files
                for file_path in backup_dir.glob('*.json'):
                    shutil.copy2(file_path, self.db_path / file_path.name)
                
                logger.info(f"Database restored from {backup_path}")
                return True
            except Exception as e:
                logger.error(f"Restore failed: {e}")
                return False
        
        # Clear current collections from memory
        async with self._global_lock:
            self.collections.clear()
        
        return await loop.run_in_executor(None, _restore)
    
    async def close(self):
        """Close the database (cleanup resources)"""
        async with self._global_lock:
            self.collections.clear()


# Convenience functions for common operations
async def create_unique_id() -> str:
    """Generate a unique ID"""
    return str(uuid.uuid4())


async def create_timestamp() -> float:
    """Get current timestamp"""
    return time.time()


# Example usage and utility functions
class Document:
    """Helper class for document-style operations"""
    
    def __init__(self, collection: Collection, doc_id: str):
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


# Factory function
def create_database(db_path: str = './data') -> AsyncJSONDB:
    """Factory function to create a database instance"""
    return AsyncJSONDB(db_path)