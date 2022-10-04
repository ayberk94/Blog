from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_gravatar import Gravatar
from forms import RegisterForm, LoginForm, CreatePostForm, CommentForm
from functools import wraps
from dotenv import load_dotenv
import os

load_dotenv()  #dotenv_path=r".env" default

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", 'sqlite:///blog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


def admin_required(func):
    @wraps(func)
    def admin_decorator(*args, **kwargs):
        if current_user.is_authenticated and current_user.id == 1:
            return func(*args, **kwargs)
        else:
            abort(403, description="Not authorized.")
    return admin_decorator


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("Nutzer.id"), nullable=False)
    author = db.relationship("User", back_populates="posts")
    comments = db.relationship("Comment")


class User(UserMixin, db.Model):
    __tablename__ = "Nutzer"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    posts = db.relationship("BlogPost") #, back_populates="author"     #überflüssig, da bei User-kreierung keine "BlogPost"-objects mitgegeben werden
    comments = db.relationship("Comment") #, back_populates="author"   #demnach wird auch nichts backpopulated! (äquivalent zu "Comment"-object.

class Comment(db.Model):
    __tablename__ = "Comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(300), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("Nutzer.id"), nullable=False)
    author = db.relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"), nullable=False)
    post = db.relationship("BlogPost", back_populates="comments")


# db.create_all()


gravatar = Gravatar(app, size=100, rating='g', default='wavatar',
                    force_default=False, force_lower=False, use_ssl=False, base_url=None)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        email = register_form.email.data
        if User.query.filter_by(email=email).first():
            flash("You are already registered. Log in instead")
            return redirect(url_for('login'))
        else:
            name = register_form.name.data
            password_unhashed = register_form.passwort.data
            password_hashed = generate_password_hash(password_unhashed, salt_length=10)
            user_to_add = User(name=name, email=email, password=password_hashed)
            db.session.add(user_to_add)
            db.session.commit()

        login_user(user_to_add)

        return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=register_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.passwort.data
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("You are not registered. Do this now instead")
            return redirect(url_for('register'))
        elif not check_password_hash(user.password, password):
            flash("wrong password.")
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=login_form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    comments = requested_post.comments
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("Only logged in members can comment. Log in")
            return redirect(url_for('login'))
        else:
            body = comment_form.body.data                             #das muss ich mit dem jinja filter "safe" filtern {{expression|filter}}
            author = current_user
            post = requested_post
            comment_to_add = Comment(text=body, author=author, post=post)
            db.session.add(comment_to_add)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
    return render_template("post.html", post=requested_post, form=comment_form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():                     #am ende mein contact machen. Mache einfach noch ein contace-form + sende funktion
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_required
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
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        # author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))



@app.route("/delete_comment/<int:post_id>/<int:comment_id>")
@admin_required
def delete_comment(post_id, comment_id):
    comment_to_delete = Comment.query.get(comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post_id))


@app.route("/edit_comment/<int:post_id>/<int:comment_id>", methods=["GET", "POST"])
@admin_required
def edit_comment(post_id, comment_id):
    requested_post = BlogPost.query.get(post_id)
    comments = requested_post.comments
    comment = Comment.query.get(comment_id)
    comment_form = CommentForm(body=comment.text)
    if comment_form.validate_on_submit():
        comment.text = comment_form.body.data
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))
    return render_template("post.html", post=requested_post, form=comment_form, comments=comments)



if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)