# AsyncJSONDB Reference Documentation

## Overview

AsyncJSONDB is a lightweight, asynchronous JSON-based database for Python applications. It provides a simple NoSQL-like interface with persistent storage using JSON files, making it ideal for small to medium applications that need structured data persistence without the overhead of a full database server.

## Features

- **Asynchronous Operations**: Full async/await support with non-blocking I/O
- **Concurrent Access**: Thread-safe operations with asyncio locks
- **Atomic Writes**: Safe file operations with backup/recovery mechanisms
- **Cross-Platform**: Handles Windows file locking and Unix atomic operations
- **Caching**: Built-in caching with configurable TTL for performance
- **Error Handling**: Comprehensive error detection and recovery
- **Backup/Restore**: Built-in database backup and restore functionality

## Quick Start

```python
import asyncio
from db import AsyncJSONDB, create_database

async def main():
    # Create database instance
    db = create_database('./my_data')
    
    # Get a collection (auto-creates if doesn't exist)
    users = await db.get_collection('users')
    
    # Basic operations
    await users.set('user1', {'name': 'John', 'email': 'john@example.com'})
    user = await users.get('user1')
    print(user)  # {'name': 'John', 'email': 'john@example.com'}
    
    # Close database
    await db.close()

# Run the example
asyncio.run(main())
```

## API Reference

### AsyncJSONDB Class

The main database class that manages collections.

#### Constructor

```python
AsyncJSONDB(db_path: str = './data')
```

**Parameters:**
- `db_path`: Directory path where JSON files will be stored

#### Methods

##### get_collection(name: str) → Collection
Get or create a collection.

```python
collection = await db.get_collection('users')
```

##### drop_collection(name: str) → bool
Drop a collection and delete its file.

```python
success = await db.drop_collection('users')
```

##### list_collections() → List[str]
List all available collections.

```python
collections = await db.list_collections()
print(collections)  # ['users', 'products', 'orders']
```

##### backup(backup_path: str) → bool
Create a backup of the entire database.

```python
success = await db.backup('./backup/2023-12-01')
```

##### restore(backup_path: str) → bool
Restore database from a backup.

```python
success = await db.restore('./backup/2023-12-01')
```

##### close()
Close the database and cleanup resources.

```python
await db.close()
```

### Collection Class

Represents a collection (table) in the database.

#### Basic Operations

##### get(key: str) → Optional[Any]
Get a value by key.

```python
value = await collection.get('user123')
```

##### set(key: str, value: Any) → bool
Set a value by key.

```python
await collection.set('user123', {'name': 'Alice', 'age': 30})
```

##### delete(key: str) → bool
Delete a value by key.

```python
deleted = await collection.delete('user123')
```

##### exists(key: str) → bool
Check if a key exists.

```python
exists = await collection.exists('user123')
```

#### Bulk Operations

##### keys() → List[str]
Get all keys in the collection.

```python
all_keys = await collection.keys()
```

##### values() → List[Any]
Get all values in the collection.

```python
all_values = await collection.values()
```

##### items() → List[tuple]
Get all key-value pairs.

```python
all_items = await collection.items()
for key, value in all_items:
    print(f"{key}: {value}")
```

##### clear() → bool
Clear all data from the collection.

```python
await collection.clear()
```

##### count() → int
Get the number of items in the collection.

```python
item_count = await collection.count()
```

#### Advanced Operations

##### find(filter_func: Optional[Callable] = None, limit: Optional[int] = None) → List[Dict[str, Any]]
Find items with optional filtering.

```python
# Find all users over 18
def adult_filter(item):
    return item.get('age', 0) > 18

adults = await collection.find(adult_filter, limit=10)

# Get all items
all_items = await collection.find()
```

##### update(key: str, updates: Dict[str, Any]) → bool
Update specific fields of a record.

```python
# Update only the email field
success = await collection.update('user123', {'email': 'newemail@example.com'})
```

##### increment(key: str, field: str = 'value', amount: Union[int, float] = 1) → Union[int, float]
Increment a numeric field.

```python
# Increment page views
new_count = await collection.increment('page_views', 'count', 1)

# Increment a simple numeric value
new_value = await collection.increment('counter')
```

### Document Class

Helper class for document-style operations with automatic metadata.

#### Constructor

```python
Document(collection: Collection, doc_id: str)
```

#### Methods

##### save(data: Dict[str, Any]) → bool
Save document data with automatic metadata.

```python
doc = Document(collection, 'user123')
await doc.save({'name': 'John', 'email': 'john@example.com'})
# Automatically adds _id and _updated fields
```

##### load() → Optional[Dict[str, Any]]
Load document data.

```python
data = await doc.load()
```

##### delete() → bool
Delete the document.

```python
deleted = await doc.delete()
```

##### update_fields(updates: Dict[str, Any]) → bool
Update specific fields with automatic timestamp.

```python
await doc.update_fields({'email': 'new@example.com'})
# Automatically updates _updated field
```

### Utility Functions

##### create_unique_id() → str
Generate a unique ID using UUID4.

```python
unique_id = await create_unique_id()
```

##### create_timestamp() → float
Get current timestamp.

```python
timestamp = await create_timestamp()
```

##### create_database(db_path: str = './data') → AsyncJSONDB
Factory function to create a database instance.

```python
db = create_database('./my_app_data')
```

## Usage Examples

### User Management System

```python
import asyncio
from db import create_database, Document, create_unique_id

async def user_management_example():
    db = create_database('./user_data')
    users = await db.get_collection('users')
    
    # Create a new user
    user_id = await create_unique_id()
    user_doc = Document(users, user_id)
    
    await user_doc.save({
        'name': 'Alice Johnson',
        'email': 'alice@example.com',
        'role': 'admin',
        'active': True
    })
    
    # Find all active users
    active_users = await users.find(
        lambda user: user.get('active', False),
        limit=50
    )
    
    # Update user role
    await user_doc.update_fields({'role': 'moderator'})
    
    # Get user count
    total_users = await users.count()
    print(f"Total users: {total_users}")
    
    await db.close()

asyncio.run(user_management_example())
```

### Shopping Cart System

```python
async def shopping_cart_example():
    db = create_database('./shop_data')
    carts = await db.get_collection('shopping_carts')
    
    user_id = 'user123'
    
    # Initialize cart
    await carts.set(user_id, {'items': [], 'total': 0.0})
    
    # Add item to cart
    cart = await carts.get(user_id)
    cart['items'].append({
        'product_id': 'prod456',
        'name': 'Python Book',
        'price': 29.99,
        'quantity': 1
    })
    cart['total'] = sum(item['price'] * item['quantity'] for item in cart['items'])
    
    await carts.set(user_id, cart)
    
    # Increment visit counter
    await carts.increment('visit_counter', 'visits', 1)
    
    await db.close()
```

### Configuration Management

```python
async def config_example():
    db = create_database('./config')
    settings = await db.get_collection('app_settings')
    
    # Set default configuration
    default_config = {
        'debug': False,
        'max_connections': 100,
        'timeout': 30,
        'features': {
            'caching': True,
            'logging': True
        }
    }
    
    await settings.set('app_config', default_config)
    
    # Update specific setting
    await settings.update('app_config', {
        'features': {'caching': True, 'logging': True, 'metrics': True}
    })
    
    # Get configuration
    config = await settings.get('app_config')
    print(f"Debug mode: {config['debug']}")
    
    await db.close()
```

## Error Handling

### DatabaseError Exception

All database operations can raise `DatabaseError` exceptions:

```python
from db import DatabaseError

try:
    await collection.set('key', 'value')
except DatabaseError as e:
    print(f"Database error: {e}")
    # Handle the error appropriately
```

### Common Error Scenarios

- **File Permission Issues**: Ensure the application has read/write access to the database directory
- **Disk Space**: Monitor available disk space for write operations
- **Concurrent Access**: The library handles this automatically with locks
- **JSON Corruption**: Automatic detection and error reporting for corrupted files

## Performance Considerations

### Caching

The library includes built-in caching with a 1-second TTL by default:

```python
# Cache configuration is automatic
# Repeated reads within 1 second use cached data
data1 = await collection.get('key')  # Reads from file
data2 = await collection.get('key')  # Uses cache
```

### Best Practices

1. **Batch Operations**: Group multiple operations when possible
2. **Reasonable Collection Sizes**: Keep collections under 10,000 items for optimal performance
3. **Close Resources**: Always call `await db.close()` when done
4. **Error Handling**: Wrap database operations in try-catch blocks
5. **Backup Regularly**: Use the built-in backup functionality

### Memory Usage

- Collections are cached in memory with a TTL
- Large datasets should be paginated using the `limit` parameter in `find()`
- Consider splitting large datasets across multiple collections

## Thread Safety

AsyncJSONDB is designed for use in asyncio applications:

- **Asyncio Safe**: All operations use asyncio locks
- **Not Thread Safe**: Don't use across multiple threads without additional synchronization
- **Concurrent Async**: Multiple async operations can safely run concurrently

## File Structure

```
./data/
├── users.json          # Users collection
├── products.json       # Products collection
└── settings.json       # Settings collection
```

Each collection is stored as a separate JSON file with the collection name.

## Migration and Compatibility

### Backing Up Data

```python
# Create timestamped backup
import datetime
timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
await db.backup(f'./backups/backup_{timestamp}')
```

### Data Format

Collections are stored as standard JSON files and can be manually edited if needed:

```json
{
  "user123": {
    "name": "John Doe",
    "email": "john@example.com",
    "_id": "user123",
    "_updated": 1701234567.89
  }
}
```

## Limitations

- **Single Machine**: Not designed for distributed systems
- **No Indexing**: Sequential search for complex queries
- **JSON Serialization**: Limited to JSON-serializable data types
- **File System Dependent**: Performance varies with underlying file system
- **Memory Usage**: Entire collections cached in memory

## Integration Examples

### FastAPI Integration

```python
from fastapi import FastAPI
from db import create_database

app = FastAPI()
db = create_database('./api_data')

@app.on_event("startup")
async def startup():
    global db
    db = create_database('./api_data')

@app.on_event("shutdown")
async def shutdown():
    await db.close()

@app.get("/users/{user_id}")
async def get_user(user_id: str):
    users = await db.get_collection('users')
    user = await users.get(user_id)
    return user or {"error": "User not found"}
```

### Django Integration

```python
# In Django, use database in async views
from django.http import JsonResponse
from db import create_database

async def async_user_view(request, user_id):
    db = create_database('./django_data')
    users = await db.get_collection('users')
    user = await users.get(user_id)
    await db.close()
    return JsonResponse(user or {"error": "User not found"})
```

This reference covers all the essential features and usage patterns for AsyncJSONDB. For additional examples or specific use cases, refer to the inline documentation in the source code.