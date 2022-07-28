
# from base64 import decode
# from os import access
from flask import Flask, jsonify , make_response, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, create_refresh_token, decode_token,JWTManager, jwt_required
from flask_sqlalchemy import SQLAlchemy



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://chidera:""@localhost/blog"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = "38skjhdjk837shkdjh939shdkh8273khjha873987hdkjhd83787ajhmnbd"
jwt = JWTManager(app)
db = SQLAlchemy(app) # declaring databse contexts



class Blog(db.Model):
    id = db.Column(db.Integer ,nullable=False, primary_key=True)
    title = db.Column(db.String(50), nullable=False, unique=True)
    author = db.Column(db.String(20), nullable=False)

class User(db.Model):
    id = db.Column(db.Integer,nullable=False, primary_key=True)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(500), nullable=False)

@app.get("/")
def handle_home():
    return {"info": "this is the home route"}



@app.post("/api/blog")
def handle_blog():
    access_token = request.headers.get("Authorization")
    if not access_token : 
        return make_response(jsonify({"message": "Not authorized to perform this action"}))

    token = access_token.split(" ")
    # try :
    decoded_token = decode_token(token[1])
    user = decoded_token['sub']
    # except Exception as e:
    #     return make_response(jsonify({"message": "invalid user token"}))
    data = request.json
    title = data['title']

    blog = Blog(title=title,author=user['email'])
    db.session.add(blog)
    db.session.commit()

    return make_response(jsonify({"data": "blog created successful", "blog":blog.author}))


@app.get("/api/blog")
def handle_get_all_post():
    blogs = Blog.query.filter().all()
    content = []
    for blog in blogs:
        output =  {
            "id": blog.id,
            "title":blog.title,
            "author": blog.author
        }
        content.append(output)
    
    return make_response(jsonify({"blogs":content}))

@app.delete ('/api/<id>')
def delete_post(id):
    output = Blog.query.get(id)
    if output is None :
        return{"404": "Not Found"}
    db.session.delete(output)
    db.session.commit()
    return {"Msg": "Deleting process done"}
    


@app.get('/api/<id>')
def get_info(id):
    data = Blog.query.get(id)
    if data is None:
        return {"404": "NONE"}
    return {"id" :data.id, "author": data.author, "title": data.title}

@app.delete('/api/delete')
def delete_all():
    data = Blog.query.filter().all()
    db.session.delete(data)
    db.session.commit()
    return {"msg" : "done"}


@app.post("/api/register")
def register_handler():
    data = request.json
    email = data['email'],
    password = data['password']
    hashed_pw =generate_password_hash(password)
    user = User.query.filter_by(email = email).first_or_404()
    if user:
        return make_response(jsonify({"message": "email already in use"}))

    accountUser = User(email=email, password=hashed_pw)
    db.session.add(accountUser)
    db.session.commit()

    return make_response(jsonify({"message": "user created successfull", "data": {
        "email": accountUser.email,
        "password": accountUser.password    
    }}))

@app.post("/api/login")
def handle_login():
    data = request.json
    email = data['email']
    passwd = data["password"]

    user = User.query.filter_by(email=email).first()

    if not user: 
        return make_response(jsonify({"message" :"user is not registered"}))

    if check_password_hash(user.password, passwd) :
        access_token = create_access_token({"userId": user.id, "email": user.email})
        return make_response(jsonify({"message": "logged in", "access_token":access_token}))
    else:   
        return make_response(jsonify({"message" : "incorrect password"}))

if __name__ == "__main__":
    app.run(debug=True)
