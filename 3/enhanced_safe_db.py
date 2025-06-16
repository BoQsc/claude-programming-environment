# transactions_as_sync.py - Understanding transactions as statement synchronization

import asyncio
from enhanced_safe_db import create_database

async def demonstrate_synchronization_concept():
    """Show how transactions synchronize multiple statements"""
    
    print("💡 Transactions = Synchronized Statements")
    print("=" * 50)
    
    db = create_database()
    
    # Setup
    accounts = await db.get_collection("accounts")
    await accounts.set("alice", {"balance": 1000})
    await accounts.set("bob", {"balance": 500})
    
    print("\n🔄 WITHOUT Synchronization (Dangerous):")
    print("-" * 40)
    
    # Simulate what happens without synchronization
    alice = await accounts.get("alice")
    bob = await accounts.get("bob")
    
    print(f"Before: Alice=${alice['balance']}, Bob=${bob['balance']}")
    print("Executing: Transfer $200 from Alice to Bob")
    
    # Statement 1: Deduct from Alice
    alice["balance"] -= 200
    await accounts.set("alice", alice)
    print(f"Step 1 ✅: Alice balance = ${alice['balance']}")
    
    # 💥 Imagine crash/error happens here!
    print("💥 [SIMULATED CRASH] - What if program crashes here?")
    print("   Result: Alice lost $200, Bob gained nothing!")
    print("   Money disappeared into the void! 😱")
    
    # Statement 2: Add to Bob (this might not execute!)
    bob["balance"] += 200
    await accounts.set("bob", bob)
    print(f"Step 2 ✅: Bob balance = ${bob['balance']}")
    
    print("\n🔒 WITH Synchronization (Safe):")
    print("-" * 40)
    
    # Reset balances
    await accounts.set("alice", {"balance": 1000})
    await accounts.set("bob", {"balance": 500})
    
    alice = await accounts.get("alice")
    bob = await accounts.get("bob")
    print(f"Before: Alice=${alice['balance']}, Bob=${bob['balance']}")
    
    try:
        async with db.transaction() as tx:
            print("🔒 SYNCHRONIZED BLOCK START")
            
            # Get fresh data
            alice = await tx.get("accounts", "alice")
            bob = await tx.get("accounts", "bob")
            
            # Statement 1: Deduct from Alice (staged)
            await tx.set("accounts", "alice", {
                **alice, 
                "balance": alice["balance"] - 200
            })
            print("   📝 Statement 1: Alice deduction staged")
            
            # Statement 2: Add to Bob (staged)
            await tx.set("accounts", "bob", {
                **bob,
                "balance": bob["balance"] + 200
            })
            print("   📝 Statement 2: Bob addition staged")
            
            print("   💾 COMMIT: Both statements execute together atomically")
            print("🔓 SYNCHRONIZED BLOCK END")
            
            # Both statements happened together!
            
    except Exception as e:
        print(f"   🔄 ROLLBACK: If ANY statement fails, ALL are undone: {e}")
    
    # Check final result
    alice_final = await accounts.get("alice")
    bob_final = await accounts.get("bob")
    print(f"After: Alice=${alice_final['balance']}, Bob=${bob_final['balance']}")
    print("✅ Money conservation: $1500 total (before and after)")

async def show_synchronization_patterns():
    """Show common synchronization patterns"""
    
    print("\n📋 Common Synchronization Patterns")
    print("=" * 50)
    
    db = create_database()
    
    print("\n1️⃣ Multiple Related Updates (Synchronize 3 statements):")
    
    try:
        async with db.transaction() as tx:
            print("🔒 Synchronizing: User + Profile + Permissions")
            
            # All 3 statements must succeed together
            await tx.set("users", "john", {
                "username": "john",
                "email": "john@example.com",
                "status": "active"
            })
            print("   📝 Statement 1: User record staged")
            
            await tx.set("profiles", "john", {
                "display_name": "John Doe",
                "bio": "Developer"
            })
            print("   📝 Statement 2: Profile record staged")
            
            await tx.set("permissions", "john", {
                "role": "user",
                "permissions": ["read", "write"]
            })
            print("   📝 Statement 3: Permissions staged")
            
            print("   💾 All 3 statements commit together!")
            
    except Exception as e:
        print(f"   🔄 If ANY of the 3 fail, ALL are rolled back: {e}")
    
    print("\n2️⃣ Conditional Logic (Synchronize validation + action):")
    
    inventory = await db.get_collection("inventory")
    await inventory.set("widget", {"stock": 5, "reserved": 0})
    
    try:
        async with db.transaction() as tx:
            print("🔒 Synchronizing: Stock check + reservation")
            
            # Statement 1: Check current stock
            item = await tx.get("inventory", "widget")
            available = item["stock"] - item["reserved"]
            print(f"   📋 Statement 1: Check availability = {available}")
            
            # Statement 2: Reserve items (only if available)
            if available >= 3:
                await tx.set("inventory", "widget", {
                    **item,
                    "reserved": item["reserved"] + 3
                })
                print("   📝 Statement 2: Reserved 3 items")
                print("   💾 Both check + reservation happen atomically!")
            else:
                raise Exception("Not enough stock")
                
    except Exception as e:
        print(f"   🔄 Check + reservation synchronized: {e}")
    
    print("\n3️⃣ Batch Operations (Synchronize many statements):")
    
    try:
        async with db.transaction() as tx:
            print("🔒 Synchronizing: Batch inventory update")
            
            # Multiple related changes
            changes = [
                ("widget", {"stock": 10}),
                ("gadget", {"stock": 5}),
                ("doohickey", {"stock": 8})
            ]
            
            for i, (item_id, updates) in enumerate(changes):
                await tx.set("inventory", item_id, updates)
                print(f"   📝 Statement {i+1}: Updated {item_id}")
            
            print(f"   💾 All {len(changes)} updates commit together!")
            
    except Exception as e:
        print(f"   🔄 All {len(changes)} updates rolled back: {e}")

async def show_mental_model():
    """Show the mental model for thinking about transactions"""
    
    print("\n🧠 Mental Model: Transactions as Synchronized Blocks")
    print("=" * 60)
    
    print("""
🔓 Normal Code:                    🔒 Synchronized Code:
─────────────────                  ──────────────────────
statement1()                       async with transaction:
statement2()        💥 Could            statement1()     
statement3()        💥 fail here        statement2()     } All or nothing
statement4()        💥 partially        statement3()     
                                        statement4()     

❌ Problem:                        ✅ Solution:
- Partial execution                - All statements grouped
- Inconsistent state              - Atomic execution  
- Hard to recover                 - Automatic rollback
                                  - Consistent state guaranteed
    """)
    
    print("\n🎯 When to Synchronize Statements:")
    print("✅ When statements are RELATED and must happen together")
    print("✅ When partial execution would corrupt your data")
    print("✅ When you need 'all or nothing' behavior")
    print("\n❌ When NOT to synchronize:")
    print("❌ When statements are independent") 
    print("❌ When partial execution is acceptable")
    print("❌ When you're just doing single operations")
    
    print("\n💡 Think of it like:")
    print("   🏠 Building a house: Foundation + Walls + Roof must all succeed")
    print("   💰 ATM withdrawal: Check balance + Deduct money + Dispense cash")
    print("   📦 Order: Charge card + Reserve item + Create shipping label")
    print("   📧 Email signup: Create account + Send welcome email + Add to mailing list")

async def demonstrate_real_world_sync():
    """Real-world example of statement synchronization"""
    
    print("\n🌍 Real-World Example: E-commerce Order")
    print("=" * 50)
    
    db = create_database()
    
    # Setup data
    users = await db.get_collection("users")
    products = await db.get_collection("products")
    orders = await db.get_collection("orders")
    inventory = await db.get_collection("inventory")
    
    await users.set("customer1", {"name": "Alice", "balance": 500.0})
    await products.set("laptop", {"name": "Laptop", "price": 400.0})
    await inventory.set("laptop", {"stock": 3})
    
    print("Setting up e-commerce order...")
    print("Customer: Alice with $500")
    print("Product: Laptop for $400") 
    print("Stock: 3 laptops available")
    
    print("\n🔒 Synchronizing 4 statements for order processing:")
    
    try:
        async with db.transaction() as tx:
            # All these statements must succeed together!
            
            # Statement 1: Validate customer has money
            customer = await tx.get("users", "customer1")
            product = await tx.get("products", "laptop")
            stock = await tx.get("inventory", "laptop")
            
            print("   📋 Statement 1: Validation checks")
            if customer["balance"] < product["price"]:
                raise Exception("Insufficient funds")
            if stock["stock"] < 1:
                raise Exception("Out of stock")
            
            # Statement 2: Charge customer
            await tx.set("users", "customer1", {
                **customer,
                "balance": customer["balance"] - product["price"]
            })
            print(f"   💰 Statement 2: Charged customer ${product['price']}")
            
            # Statement 3: Reduce inventory
            await tx.set("inventory", "laptop", {
                **stock,
                "stock": stock["stock"] - 1
            })
            print("   📦 Statement 3: Reduced inventory by 1")
            
            # Statement 4: Create order record
            import uuid
            order_id = str(uuid.uuid4())
            await tx.set("orders", order_id, {
                "customer": "customer1",
                "product": "laptop",
                "amount": product["price"],
                "status": "confirmed"
            })
            print(f"   📋 Statement 4: Created order {order_id[:8]}")
            
            print("   💾 All 4 statements committed atomically!")
            print("   ✅ Order processed successfully!")
            
    except Exception as e:
        print(f"   🔄 All 4 statements rolled back: {e}")
        print("   ✅ Data remains consistent!")
    
    # Show final state
    customer_final = await users.get("customer1")
    stock_final = await inventory.get("laptop")
    order_count = await orders.count()
    
    print(f"\nFinal synchronized state:")
    print(f"   Customer balance: ${customer_final['balance']}")
    print(f"   Laptop stock: {stock_final['stock']}")
    print(f"   Orders created: {order_count}")
    print("   💡 All changes happened together - perfectly synchronized!")

if __name__ == "__main__":
    asyncio.run(demonstrate_synchronization_concept())
    asyncio.run(show_synchronization_patterns())
    asyncio.run(show_mental_model())
    asyncio.run(demonstrate_real_world_sync())