from flask import Flask, render_template, redirect, url_for, flash,g
from werkzeug.exceptions import abort
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar
from functools import wraps

Base = declarative_base()
app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# Gravatar for images for the comment section
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

##CONFIGURE TABLES

class User(UserMixin, db.Model):
    # Parent Table
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    posts = db.relationship('BlogPost', back_populates='author')
    comments = db.relationship('Comment', back_populates='comment_author')

class BlogPost(db.Model, UserMixin):
    # Child Table
    # Parent table when linking it with the Comment Table named comments
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.relationship('User', back_populates='posts')
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comments = db.relationship('Comment', back_populates= 'parent_post')


class Comment(db.Model, UserMixin):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(250), nullable= False)
    comment_author = db.relationship('User', back_populates='comments')
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    parent_post = db.relationship('BlogPost', back_populates='comments')
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))

db.create_all()

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    id = current_user.get_id()
    if id == None:
        return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)
    else:
        return render_template("index.html", all_posts=posts, logged_in= current_user.is_authenticated, user_id= int(id))


@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name= form.name.data
        email= form.email.data
        password= form.password.data
        user = User.query.filter_by(email= email).first()
        if user:
            flash("This email already exist. Please Log in with this email!")
            return redirect(url_for("login"))
        else:
            new_user = User(name= name, email= email, password= generate_password_hash(password, method='pbkdf2:sha256', salt_length=8))
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email= email).first()
        if not user:
            flash("Email Address has not been found. Please try again with different email address.")
            return redirect(url_for("login"))
        elif check_password_hash(user.password, password):
            login_user(user)
            posts = BlogPost.query.all()
            return render_template("index.html", all_posts=posts, logged_in= current_user.is_authenticated, user_id=user.id)
        else:
            flash("The password is incorrect. Please try again.")
            return redirect(url_for("login"))
    return render_template("login.html", form= form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()

    # Posting the Comments
    if form.validate_on_submit():
        if current_user.is_authenticated:
            user_comment = form.comment.data
            entry = Comment(text= user_comment, author_id=int(current_user.get_id()), post_id= post_id)
            db.session.add(entry)
            db.session.commit()
            form.comment.data=''
            return redirect(url_for("show_post", post_id= post_id))
        else:
            flash("You need to login first login, then comment")
            return redirect(url_for('login'))

    if current_user.get_id() == None:
        return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated, form=form)
    else:
        return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated, user_id=int(current_user.get_id()), form=form)


@app.route("/about")
def about():
    return render_template("about.html", logged_in= current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in= current_user.is_authenticated)


# My created Decorator ############################################################################
def admin_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user_id = current_user.get_id()
        if int(user_id) > 1:
            return abort(403)
        else:
            print("Function has run.")
            return f(*args, **kwargs)
    return wrapper


@app.route("/new-post", methods=["POST","GET"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in= current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=["POST", "GET"])
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in= current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
