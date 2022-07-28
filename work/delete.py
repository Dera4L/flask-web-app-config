from main import db, engine, Blog,app, request
Local_session = db(bind=engine)

@app.delete("/api/blog")
def delete_users():
    user_to_delete=Local_session.query(Blog).filter(Blog.author=="dere").first()
    Local_session.delete(user_to_delete)
    Local_session.commit()