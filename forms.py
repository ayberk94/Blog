from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, URL, Email, ValidationError
from flask_ckeditor import CKEditorField



def lenght_checker(form, field):
    if len(field.data) < 5:
        raise ValidationError("too short")





class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    name = StringField(label="name", validators=[DataRequired()], render_kw={"placeholder": "name"})
    email = EmailField(label="email", validators=[DataRequired(), Email()], render_kw={"placeholder": "email"})
    passwort = PasswordField(label="password", validators=[DataRequired(), lenght_checker], render_kw={"placeholder": "password"})
    submit = SubmitField(label="Submit")



class LoginForm(FlaskForm):
    email = EmailField(label="email", validators=[DataRequired(message="give email"), Email(message="no valid email")], render_kw={"placeholder": "email"})
    passwort = PasswordField(label="password", validators=[DataRequired(message="give password")], render_kw={"placeholder": "password"})
    submit = SubmitField(label="Submit")


class CommentForm(FlaskForm):
    body = CKEditorField(label="Comment", validators=[DataRequired()])
    submit = SubmitField(label="Submit")







