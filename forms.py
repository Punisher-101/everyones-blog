from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from flask_ckeditor import CKEditorField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditorField
from wtforms.fields.html5 import EmailField

##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


##Wtform
class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Me Up!')

## Login Form
class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

# CommentForm
class CommentForm(FlaskForm):
    comment = CKEditorField('')
    submit = SubmitField("Submit")