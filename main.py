 
import webapp2
import cgi
import re
import os
import jinja2
import hashlib
import hmac
import random
import json
import urllib2
from datetime import datetime,timedelta
from xml.dom import minidom
from string import letters
from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),autoescape = True)

##
# Security module
##
SECRECT = 'codd'
def render_str(template,**params):
	t = jinja_env.get_template(template)
	return t.render(params)
def hash_str(s):
	return hmac.new(SECRECT,s).hexdigest()
def make_secure_val(s):
	return "%s|%s" % (s,hash_str(s))
def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val
def make_salt():
	return ''.join(random.choice(letters) for x in xrange(5))
def make_pw_hash(name,pw,salt=None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name+pw+salt).hexdigest()
	return '%s|%s' % (salt,h)
def valid_pw(name,pw,h):
	salt = h.splite('|')[0]
	return h == make_pw_hash(name,pw,salt)
##
# Main module
##
def age_str(age):
	s = 'queried %s seconds ago'
	age = int(age)
	if age == 1:
		s = s.replace('seconds','second')
	return s % age
def age_set(key,val):
	save_time = datetime.utcnow()
	memcache.set(key,(val,save_time))

def age_get(key):
	r = memcache.get(key)
	if r:
		val,save_time = r
		age = (datetime.utcnow() - save_time).total_seconds()
	else:
		val,age = None,0
	return val,age

def add_post(ip,post):
	post.put()
	get_posts(update=True)
	return str(post.key().id())

def get_posts(update=False):
	g = Blog.all().order('-created').fetch(limit=10)
	mc_key = 'BLOGS'
	posts,age = age_get(mc_key)
	if update or posts is None:
		posts = list(g)
		age_set(mc_key,posts)
	return posts,age

class Handler(webapp2.RequestHandler):
	def write(self,*a,**kw):	
		self.response.out.write(*a,**kw)

	def render_str(self,template,**params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self,template,**kw):
		self.write(self.render_str(template,**kw))

	def render_json(self,d):
		json_text = json.dumps(d)
		self.response.headers['Content-Type'] = 'application/json;charset=UTF-8'
		self.write(json_text)
	
	def read_secure_cookie(self,name):	
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def initialize(self,*a,**kw):
		webapp2.RequestHandler.initialize(self,*a,**kw)
		uid = self.read_secure_cookie('user_id')
		if uid:
			self.user = User.by_id(int(uid))
		if self.request.url.endswith('.json'):
			self.format='json'
		else:
			self.format='html'

class RealMainPage(Handler):
	def get(self):
		#self.render("welcome.html",content="Hello,welcome to the world of Sky Dragon")
		self.response.headers['Content-Type'] = 'text/plain'
		visits = 0
		visits_cookie_val = self.request.cookies.get('visits')

		if visits_cookie_val:
			cookie_val = check_secure_val(visits_cookie_val)
			if cookie_val:
				visits = int(cookie_val)
		visits = visits + 1
		new_cookie_val = make_secure_val(str(visits))
		self.response.headers.add_header('Set-Cookie','visits=%s' % new_cookie_val)
		if visits>10000:
			self.write("You are the best ever!")
		else:
			self.write("You've been here %s times!" % visits)
		
	def write(self,content):
		self.response.out.write(content)
###### blog stuff

class MainPage(Handler):
	def get(self):
		#posts = db.GqlQuery("select * from Blog order by created desc limit 10")
		posts,age = get_posts()
		if self.format == 'html':
			self.render('mainblog.html',posts = posts,age = age_str(age))
		else:
			self.render_json([p.as_dict() for p in posts])
def blog_key(name='default'):
	return db.Key.from_path('blogs',name)

class NewPost(Handler):
	def render_front(self,subject="",blog="",error=""):
		self.render("new.html",subject=subject,blog=blog,error=error)

	def get(self):
		self.render_front()
	
	def post(self):
		subject = self.request.get("subject")
		blog = self.request.get("blog")

		if subject and blog:
			capture = Blog(parent=blog_key(),subject=subject,blog=blog)
			capture.put()
			self.redirect('/blog/%s' % str(capture.key().id()))

		else:
			error = "we need both a subject and s"
			self.render_front(subject,blog,error)
class Postpage(Handler):
	def get(self,post_id):
		post_key = 'blogs_' + post_id
		post,age = age_get(post_key)

		if not post:
			key = db.Key.from_path('Blog',int(post_id),parent=blog_key())
			post = db.get(key)
			age_set(post_key,post)
			age = 0

		if not post:
			self.error(404)
			return
		if self.format == 'html':
			self.render("permalink.html",post=post,age = age_str(age))
		else:
			self.render_json(post.as_dict())

		
class Blog(db.Model):
	subject = db.StringProperty(required = True)
	blog = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
	def render(self):
		self._render_text = self.blog.replace('\n','<br>')
		t = jinja_env.get_template("post.html")
		return t.render(p = self)
	def as_dict(self):
		time_fmt='%c'
		d={
		'subject':self.subject,
		'content':self.blog,
		'created':self.created.strftime(time_fmt),
		'last_modified':self.last_modified.strftime(time_fmt)}
		return d 

####
#  Sign up module
###
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email_cc):
	return  email_cc or EMAIL_RE(email_cc)

class BlogHandler(webapp2.RequestHandler):
	def write(self,*a,**kw):	
		self.response.out.write(*a,**kw)
	def render_str(self,template,**params):
		#params['user'] = self.user
		t = jinja_env.get_template(template)
		return t.render(params)		
	def render(self,template,**kw):
		self.write(self.render_str(template,**kw))
	def set_secure_cookie(self,name,val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s;Path=/' % (name,val))
	def read_secure_cookie(self,name):	
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)
	def login(self,user):
		self.set_secure_cookie('user_id',str(user.key().id()))
	def logout(self):
		self.response.headers.add_header('Set-Cookie','user_id=;Path=/')
	def initialize(self,*a,**kw):
		webapp2.RequestHandler.initialize(self,*a,**kw)
		uid = self.read_secure_cookie('user_id')
		if uid:
			self.user = User.by_id(int(uid))
		if self.request.url.endswith('.json'):
			self.format='json'
		else:
			self.format='html'

class SignUpPage(BlogHandler):

	def get(self):
		self.render("Signup.html")
	def post(self):
		flag = True
		username = self.request.get("username")
		if (not self.exmain_username(username)) or (not valid_username(username)) :
			error_username = "Your name is not valid!"
			flag =False
		else:
			error_username = ""
		password_first = self.request.get('password_first')
		password_verify = self.request.get('password_verify')
		if not self.exmain_password(password_first,password_verify) or not valid_password(password_first) or not valid_password(password_verify):
			error_password = "Your password does not match!"
			flag =False
		else:
			error_password = ""
		email_address = self.request.get('email_address')
		if not self.exmain_email(email_address) or not valid_email(email_address):
			error_email = "Your email is not valid!"
			flag =False
		else:
			error_email = ""

		if flag == False:
			self.render("Signup.html",username=username,password_first=password_first,password_verify=password_verify,email_address=email_address,error_username=error_username,error_password=error_password,error_email=error_email)
			#self.redirect('/signup' % str(capture.key().id()))
		else:
			#guys = db.GqlQuery("select * from User")
			u = User.by_name(username)
			if u:
				msg = "User has existed!"
				self.render("Signup.html",username=username,password_first=password_first,password_verify=password_verify,email_address=email_address,error_username=error_username,error_password=error_password,error_email=error_email,error_user_isExit=msg)
			else:
				u = User.register(username,password_first,email_address)
				u.put()
				self.login(u)
				self.redirect("/Unit3/Welcome")

	def exmain_user_exit(self,guys,username):
		for g in guys:
			if g.username == username:
				return g
	def exmain_username(self,username):
		for i in range(len(username)):
			if username[i] == " ":
				return False
		return True
	def exmain_password(self,password_first,password_verify):
		if  password_first == password_verify:
			return True
		return False
	def exmain_email(self,email_address):
		for i in range(len(email_address)):
			if email_address[i] == "@":
				return True
		return False

def user_key(group='default'):
	return db.Key.from_path('users',group)

class User(db.Model):
	username = db.StringProperty(required=True)
	pw_hash = db.StringProperty(required=True)
	email = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add=True)
	@classmethod
	def by_id(cls,uid):
		return User.get_by_id(uid,parent = user_key())
	@classmethod
	def by_name(cls,name):
		u = User.all().filter('username =',name).get()
		return u
	@classmethod
	def register(cls,username,pw,email=None):
	 	pw_hash = make_pw_hash(username,pw)
	 	return User(parent=user_key(),username=username,pw_hash=pw_hash,email=email)
	@classmethod
	def login(cls,name,pw):
		u = cls.by_name(name)
		if u and valid_pw(name,pw,u.pw_hash):
			return u
class WelcomePage(BlogHandler):
	def get(self):
		user_id = self.request.cookies.get('user_id')
		if user_id:
			user_id = int(user_id)
			u_for_name = User.by_id(user_id)
			#self.response.out.write("hahah")
			self.render('welcome1.html',username=u_for_name.username)
		else:
			self.redirect('/Signup')
		
class LoginPage(BlogHandler):
	def get(self):
		self.render("login.html")
	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		if not (valid_username(username) and valid_password(password)):
			msg = "invalid login"
			self.render("login.html",username=username,password=password,error_login=msg)
		else:
			u = User.by_name(username)
			if u:
				self.login(u)
				self.redirect("/Unit3/Welcome")
			else:
				msg = "invalid login"
				self.render("login.html",username=username,password=password,error_login=msg)
class LogoutPage(BlogHandler):
	def get(self):
		self.logout()
		self.redirect('/Signup')
	
####
# Art Module
####
IP_URL="http://api.hostip.info/?ip="
GMAPS_URL='http://maps.googleapis.com/maps/api/staticmap?size=600x300&sensor=false&'
def get_coords(ip):
	url = IP_URL + ip
	content =None
	try:
		content = urllib2.urlopen(url).read()
	except URLError:
		return
	if content:
		d = minidom.parseString(content)
		coords = d.getElementsByTagName("gml:coordinates")
		if coords and coords[0].childNodes[0].nodeValue:
			lon,lat = coords[0].childNodes[0].nodeValue.split(',')
			return db.GeoPt(lat,lon)
def gmaps_img(points):
	markers ='&'.join('markers=%s,%s' %(p.lat,p.lon) for p in points)
	return GMAPS_URL + markers

class ArtHandler(webapp2.RequestHandler):
	def write(self,*a,**kw):	
		self.response.out.write(*a,**kw)

	def render_str(self,template,**params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self,template,**kw):
		self.write(self.render_str(template,**kw))

class ArtPage(ArtHandler):
	def render_front(self,title="",art="",error=""):
		arts = db.GqlQuery("SELECT * FROM Art ORDER BY created DESC",art_key())
		arts = list(arts)
		point=filter(None,(a.coords for a in arts))
		img_url = None
		if point:
			img_url = gmaps_img(point)

		self.render("front2.html",title=title,art=art,error=error,arts=arts,img_url=img_url)

	def get(self):
		self.write(repr(get_coords(self.request.remote_addr)))
		self.render_front()
	def post(self):
		title = self.request.get("title")
		art = self.request.get("art")

		if title and art:
			a = Art(parent=art_key(),title = title,art = art)
			coords = get_coords(self.request.remote_addr)
			if coords:
				a.coords = coords
			a.put()
			self.redirect('/')
		else:
			error = "we need both a title and some artwork!"
			self.render_front(title,art,error)
def art_key(name='default'):
	return db.Key.from_path('arts',name)
class Art(db.Model):
	title = db.StringProperty(required = True)
	art = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	coords = db.GeoPtProperty()	

####
# Rot 13 module
####
textarea = """
	<form method="post" action="/Rot13">
	<h2> Enter some text to ROT13</h2>
	<br>
	<textarea name="content" style="height:100px; width:400px">%(content)s</textarea>
	<input type="submit">
	</form>
"""

class Rot13Handler(webapp2.RequestHandler):
	def get(self):
		self.write_textarea()
	def write_textarea(self,content=""):
		self.response.out.write(textarea % {"content":content})
	def post(self):
		content = self.request.get("content")
		content = self.ercytion(content)
		content = escape_html(content)
		self.write_textarea(content)

	def ercytion(self,content):
		copy = ""
		for i in range(len(content)):
			if ord(content[i]) >= 65 and ord(content[i]) <= 90:
				if ord(content[i]) + 13 > 90:
					copy += chr((ord(content[i])+13)%90+64)
				else:
					copy += chr(ord(content[i])+13)
			elif ord(content[i]) >= 97 and ord(content[i]) <= 122:
				if ord(content[i]) + 13 > 122:
					copy += chr((ord(content[i])+13)%122+96)
				else:
					copy += chr(ord(content[i])+13)
			else:
				copy += content[i]
		return copy


app = webapp2.WSGIApplication([
   ('/',RealMainPage), ('/blog/?(?:\.json)?', MainPage),('/blog/newpost',NewPost),('/blog/([0-9]+)(?:\.json)?',Postpage),
   ('/Signup',SignUpPage),('/Unit3/Welcome',WelcomePage),('/login',LoginPage),('/logout',LogoutPage),
   ('/art',ArtPage),
   ('/Rot13',Rot13Handler)
], debug=True)

