from datetime import date
from typing import Optional
from fastapi import FastAPI,HTTPException,Depends
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import *
from authentication import *
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm


#Database and database session
engine = create_engine('sqlite:///db.sqlite3')
Session = sessionmaker(bind=engine)
Base.metadata.create_all(engine)
app = FastAPI()


@app.get("/")
def root():
    return {"message": "Product FASTAPI"}

#User registation
@app.post("/registration")
def user_registration(username: str, email: str, password:str):
    user_session = Session()
    new_user= User(
        username=username,
        email= email,
        password=password,
    )
    # Check password length
    if len(new_user.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be longer than 8 characters")

    # Check username length
    if len(new_user.username) < 5:
        raise HTTPException(status_code=400, detail="Username must be longer than 5 characters")

    # Check email format
    if is_not_email(new_user.email):
        raise HTTPException(status_code=400, detail="Invalid email format")

    # Check if username or email already exists
    if user_session.query(User).filter(User.username == new_user.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if user_session.query(User).filter(User.email == new_user.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")

    # Hash password and mark user as verified
    new_user.password = get_password_hash(new_user.password)
    new_user.is_verified = False    #By default False , we can use verfication email to enable this

    # Add new user
    user_session.add(new_user)
    user_session.commit()
    user_session.refresh(new_user)
    user_session.close()

    return f' Welcome {new_user.username}! '

#user_login
@app.post("/user_login")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    session = Session()
    user = session.query(User).filter(User.username == form_data.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not verify_password(password, user.password):
        raise HTTPException(status_code=404, detail="Incorrect Password")
    return {"access_token": user.username, "token_type": "bearer"}

#show products
@app.get("/products")
def show_all():
    session = Session()
    return session.query(Products).all()

#add products
@app.post("/add_products")
def add_product(title: str, description: str, price: float, quantity: int, category: str, manufacturer: str):
        session = Session()
        product = Products(
            title=title,
            description=description,
            price=price,
            quantity=quantity,
            created_at=date.today(),
            in_stock=True,
            category=category,
            manufacturer=manufacturer
        )
        session.add(product)
        session.commit()
        session.close()

        return {"status_code": 200, "message": "Product added successfully"}


# Filter Products by Category
@app.get("/products/{category}")
def find_products_by_category(category: str):
    session = Session()
    products = session.query(Products).filter(Products.category == category).all()
    session.close()
    if not products:
        raise HTTPException(status_code=404, detail="Products not found for the given category")

    result = [jsonable_encoder(product) for product in products]

    return {"status_code": 200, "result": result}

# Filter product using min max price
@app.get("/filter/")
def get_filter_products(min_price: float = None, max_price: float = None):
    session = Session()
    query = session.query(Products)

    # Filter products based on the first price range if provided
    if min_price is not None:
        query = query.filter(Products.price >= min_price)
    if max_price is not None:
        query = query.filter(Products.price <= max_price)

    products = query.all()

    return products

#Update products filter by title
@app.put("/update_product/{title}")
def update_product(title: str, price: Optional[float] = None, in_stock: Optional[bool] = True):
    session = Session()
    product = session.query(Products).filter(Products.title == title).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    if price is not None:
        product.price = price
    if in_stock is not None:
        product.in_stock = in_stock

    session.commit()
    session.refresh(product)

    return JSONResponse(
        status_code=200, content={"status_code": 200, "message": "Product updated successfully"}
    )

#delete Product
@app.delete("/delete_product/{title}")
def delete_book(title: str):
    session = Session()
    product = session.query(Products).filter(Products.title == title).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    session.delete(product)
    session.commit()
    session.close()

    return JSONResponse(
        status_code=200, content={"status_code": 200, "message": "Product deleted "}
    )


