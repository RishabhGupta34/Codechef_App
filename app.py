from flask import Flask,request,url_for,redirect,render_template
#from flask_mail import Mail , Message
import flask_login
import requests
from bs4 import BeautifulSoup
#from werkzeug.security import generate_password_hash,check_password_hash
#from flask_bcrypt import check_password_hash
#from flask_bcrypt import generate_password_hash
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer,SignatureExpired,BadTimeSignature
from pymongo import MongoClient
import smtplib


app=Flask(__name__)
app.secret_key = 'A?DSGREfgska[]dkoRERWF???::HLELFS'

bcrypt = Bcrypt(app)

#app.config.from_pyfile('config.cfg')

#mail=Mail(app)


MONGODB_URI = "mongodb://test:test@ds145649.mlab.com:45649/codechefdb"
client = MongoClient(MONGODB_URI)
db = client.get_database("codechefdb")
user_record = db.user_records

s=URLSafeTimedSerializer('A?DSGREfgska[]dkoRERWF???::HLELFS')

login_manager = flask_login.LoginManager()
login_manager.init_app(app) 






#ABOUT INFO GENERATION
def aboutinfo():
    abt={}
    url="https://www.codechef.com/users/"+user_record.find_one({'email':flask_login.current_user.id})['username']
    r=requests.get(url)
    soup=BeautifulSoup(r.content,"html5lib")
    mains=soup.findAll("main")[0]
    divs=mains.findAll("div")
    abt['Name']=divs[1].div.div.div.div.header.h2.text
    lis=divs[1].findAll("li")
    for i in range(6):
        abt[lis[i].label.text]=lis[i].span.text
    for i in range(len(lis)-2,len(lis)):
        l=lis[i].text.split()
        abt[l[1]+" "+l[2]+":"]=int(l[0])
    data={}
    data['about']=abt
    user_record.update_one({'email':flask_login.current_user.id},{"$set":data})
    return user_record.find_one({'email':flask_login.current_user.id})['about']
#ABOUT INFO GENERATION END

#RATING INFO GENERATION
def ratinginfo():
    user_rating=[]
    url="https://www.codechef.com/users/"+user_record.find_one({'email':flask_login.current_user.id})['username']
    r=requests.get(url)
    soup=BeautifulSoup(r.content,"html5lib")
    mains=soup.findAll("main")[0]
    divs=mains.findAll("div")
    small=divs[1].findAll("div")
    ratings=small[0].findAll("div")[0].findAll("div")[0].findAll("div")[0].findAll("section")[1].findAll("section")
    for i in ratings:
        rat=[]
        divss=i.findAll("div")[0].findAll("div")
        rat.append(divss[1].a.text)
        rat.append(divss[2].div.a.text)
        rat.append(divss[2].strong.text)
        user_rating.append(rat)
    data={}
    data['rating']=user_rating
    user_record.update_one({'email':flask_login.current_user.id},{"$set":data})
    return user_record.find_one({'email':flask_login.current_user.id})['rating']
#RATING INFO GENERATION END

#QUESTIONS SOLVED INFO GENERATION
def ques_solved():
	headings=[]
	head_text=[]
	hrefs=[]
	all_text=[]
	url="https://www.codechef.com/users/"+user_record.find_one({'email':flask_login.current_user.id})['username']
	r=requests.get(url)
	soup=BeautifulSoup(r.content,"html5lib")
	mains=soup.findAll("main")[0]
	divs=mains.findAll("div")
	sections=divs[1].findAll("section")
	hs=sections[13].findAll("h5")
	for i in range(len(hs)):
		headings.append(hs[i].text)
	articles=sections[13].findAll("article")
	for i in range(len(articles)):
		head=(articles[i].findAll("strong"))
		head_text.append([head[j].text for j in range(len(head))])
		spans=articles[i].findAll("span")
		spans_as=[spans[k].findAll("a") for k in range(len(spans))]
		href=[]
		texts=[]
		for o in range(len(spans)):
			hr=[]
			text=[]
			for p in range(len(spans_as[o])):
				hr.append('https://www.codechef.com'+spans_as[o][p]["href"])
				text.append(spans_as[o][p].text)
			href.append(hr)
			texts.append(text)
		hrefs.append(href)
		all_text.append(texts)
	data={}
	data['questioninfo']={}
	data['questioninfo']['headings']=headings
	data['questioninfo']['head_text']=head_text
	data['questioninfo']['hrefs']=hrefs
	data['questioninfo']['all_text']=all_text
	user_record.update_one({'email':flask_login.current_user.id},{"$set":data})


#QUESTIONS SOLVED INFO GENERATION END


class User(flask_login.UserMixin):
    pass


@login_manager.user_loader
def user_loader(email):
	for i in user_record.find():
		if email==i['email']:
			user = User()
			user.id = email
			return user
	return

    


@login_manager.request_loader
def request_loader(request):
    email = request.form.get('loginemail')
    for i in user_record.find():
    	if email==i['email']:
    		user = User()
    		user.id = email

    # DO NOT ever store passwords in plaintext and always compare password
    # hashes using constant-time comparison!
    		user.is_authenticated = bcrypt.check_password(request.form['loginpass'],i[password])
    		return user
    return
    



@app.route('/login', methods=['GET', 'POST'])
def login():    
    if request.method == 'GET':
        return render_template("login.html")

    email = request.form['loginemail']
    if bcrypt.check_password_hash(user_record.find_one({'email':email})['password'],request.form['loginpass']):
        user = User()
        user.id = email
        flask_login.login_user(user)
        return redirect(url_for('home'))

    return 'Bad login'


@app.route('/home')
@flask_login.login_required
def home():
    if user_record.find_one({'email':flask_login.current_user.id})['verify']==True:
        return render_template("home.html")
    else:
        return render_template("nonverifyhome.html")

@app.route('/logout')
def logout():
    flask_login.logout_user()
    return render_template("logout.html")

@login_manager.unauthorized_handler
def unauthorized_handler():
    return render_template("unauth.html")

@app.route('/about')
def about():
    return render_template("about.html",abt=aboutinfo())

@app.route('/register',methods=['GET','POST'])
def register():
    if request.method=='GET':
        return render_template('register.html')
    elif request.method=='POST':
        users={}
        regemail=request.form.get("regemail")
        reguser=request.form.get("cusername")
        regname=request.form.get("regname")
        if request.form.get("regpass")!=request.form.get("regcpass"):
            error="Passwords don't match!!"
            return render_template("register.html",error=error)
        elif user_record.find_one({"email":regemail}):
            error="Email already Exists!!"
            return render_template("register.html",error=error)
        else:
            passw=bcrypt.generate_password_hash(request.form.get("regpass")).decode('utf-8')
            users={}
            users['name']=regname
            users['email']=regemail
            users['password']=passw
            users['username']=reguser
            users['verify']=False
            token=s.dumps(regemail,salt='email-confirm')
            #msg=Message("Confirm Email",sender="codechef.app@yahoo.com",recipients=[regemail])
            link=url_for("confirm_email",token=token,_external=True)
            msg='''Hi {} your account has been created but it has to verified first by clicking on the link given below.
                   Please note that the link will only be valid for an hour after that it will expire.

                   Your Link is {}.


                   Thank you for registering on the Codechef Website :-)

                   Regards
                   Rishabh Gupta '''.format(regname,link)
            #mail.send(msg)
            server = smtplib.SMTP("smtp.gmail.com",587)
            username="rish.gup34@gmail.com"
            password="test12345678"
            server.starttls()
            server.login(username,password)
            server.sendmail(username, regemail,msg)
            user_record.insert_one(users)
            return render_template("verifyform.html")

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email=s.loads(token,salt='email-confirm',max_age=3600)
        data={
        "verify":True
        }
        user_record.update_one({"email":email},{"$set":data})
        #msg=Message("New User!",sender="codechef.app@yahoo.com",recipients=["rish.gupta34@gmail.com"])
        msg='''Hi, Rishabh a new account has been created and verified on your Codechef Website.
                            
                        Congrats :-) '''
        #mail.send(msg)
        server = smtplib.SMTP("smtp.gmail.com",587)
        username="rish.gup34@gmail.com"
        password="test12345678"
        server.starttls()
        server.login(username,password)
        server.sendmail(username, regemail,msg)
    except SignatureExpired:
        #msg=Message("Account Deleted!",sender="codechef.app@yahoo.com",recipients=[email])
        msg='''Sorry, you were to slow in verifying your email which compelled me to delete your account.

                        No problem you can create a new account in no time.
                        {}
                            
                        Sorry for inconvenience :-(
                        Rishabh Gupta '''.format(url_for(login))
        #mail.send(msg)
        server = smtplib.SMTP("smtp.gmail.com",587)
        username="rish.gup34@gmail.com"
        password="test12345678"
        server.starttls()
        server.login(username,password)
        server.sendmail(username, regemail,msg)
        user_record.delete_one({"email":email})
        return render_template("timeexpired.html")
    except BadTimeSignature:
        return render_template("badtoken.html")
    return render_template("submitform.html")

@app.route('/solved')
def solved():
    ques_solved()
    user1=user_record.find_one({'email':flask_login.current_user.id})
    return render_template("solved.html",headings=user1['questioninfo']['headings'],head_text=user1['questioninfo']['head_text'],hrefs=user1['questioninfo']['hrefs'],all_text=user1['questioninfo']['all_text'])

@app.route('/rating')
def rating():
    return render_template("rating.html",user_rating=ratinginfo())


if __name__=="__main__":
	app.run(port=8000,debug=True)