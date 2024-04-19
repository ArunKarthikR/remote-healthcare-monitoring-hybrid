# main.py
import os
import base64
import io
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import math
from flask import Flask, render_template, Response, redirect, request, session, abort, url_for
import mysql.connector
import hashlib
from datetime import datetime
from datetime import date
import datetime
import random
from random import seed
from random import randint
from urllib.request import urlopen
import webbrowser
import rsa
#from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
#from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

from werkzeug.utils import secure_filename
from PIL import Image
#import stepic
import urllib.request
import urllib.parse
import socket    

#import seaborn as sns
#import warnings
#warnings.filterwarnings('ignore')
import csv
#import codecs
#from flask import (jsonify, request)


mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="",
  charset="utf8",
  use_pure="True",
  database="healthchain"

)
app = Flask(__name__)
##session key
app.secret_key = 'abcdef'
#######
UPLOAD_FOLDER = 'static/upload'
ALLOWED_EXTENSIONS = { 'csv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
#####
@app.route('/', methods=['GET', 'POST'])
def index():
    msg=""
    

    return render_template('web/index.html',msg=msg)

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg=""

    
    if request.method=='POST':
        uname=request.form['uname']
        pwd=request.form['pass']
        cursor = mydb.cursor()
        cursor.execute('SELECT * FROM hc_patient WHERE uname = %s AND pass = %s', (uname, pwd))
        account = cursor.fetchone()
        if account:
            session['username'] = uname
            return redirect(url_for('pat_home'))
        else:
            msg = 'Incorrect username/password!'
    return render_template('web/login.html',msg=msg)

@app.route('/login_hos', methods=['GET', 'POST'])
def login_hos():
    msg=""
    act=request.args.get("act")
    
    if request.method=='POST':
        uname=request.form['uname']
        pwd=request.form['pass']
        cursor = mydb.cursor()
        cursor.execute('SELECT * FROM hc_hospital WHERE uname = %s AND pass = %s AND status=1', (uname, pwd))
        account = cursor.fetchone()
        if account:
            session['username'] = uname
            return redirect(url_for('hos_home'))
        else:
            msg = 'Incorrect username/password!'
    return render_template('web/login_hos.html',msg=msg,act=act)

@app.route('/login_lab', methods=['GET', 'POST'])
def login_lab():
    msg=""

    
    if request.method=='POST':
        uname=request.form['uname']
        pwd=request.form['pass']
        cursor = mydb.cursor()
        cursor.execute('SELECT * FROM hc_lab WHERE uname = %s AND pass = %s AND status=1', (uname, pwd))
        account = cursor.fetchone()
        if account:
            session['username'] = uname
            return redirect(url_for('lab_upload'))
        else:
            msg = 'Incorrect username/password!'
    return render_template('web/login_lab.html',msg=msg)

@app.route('/login_chain', methods=['GET', 'POST'])
def login_chain():
    msg=""

    
    if request.method=='POST':
        uname=request.form['uname']
        pwd=request.form['pass']
        cursor = mydb.cursor()
        cursor.execute('SELECT * FROM admin WHERE username = %s AND password = %s', (uname, pwd))
        account = cursor.fetchone()
        if account:
            session['username'] = uname
            return redirect(url_for('admin'))
        else:
            msg = 'Incorrect username/password!'
    return render_template('web/login_chain.html',msg=msg)


@app.route('/reg', methods=['GET', 'POST'])
def reg():
    msg=""

    mycursor = mydb.cursor()
    if request.method=='POST':
        aadhar=request.form['aadhar']
        mobile=request.form['mobile']
        cursor = mydb.cursor()
        
        session['aadhar'] = aadhar
        session['mobile'] = mobile

        mycursor.execute("SELECT count(*) FROM hc_patient where aadhar=%s",(aadhar,))
        cnt = mycursor.fetchone()[0]
        if cnt==0:
            otp=randint(1000,9999)
            ff=open("num.txt","w")
            ff.write(str(otp))
            ff.close()
            mess="OTP: "+str(otp)
            url="http://iotcloud.co.in/testsms/sms.php?sms=emr&name=User&mess="+mess+"&mobile="+str(mobile)
           
            webbrowser.open_new(url)
            return redirect(url_for('reg_otp'))
        else:
            msg="Aadhar No. already exist!"
            
    return render_template('web/reg.html',msg=msg)

@app.route('/reg_otp', methods=['GET', 'POST'])
def reg_otp():
    msg=""


    if request.method=='POST':
        key=request.form['key']
       
        ff=open("num.txt","r")
        otp=ff.read()
        ff.close()
        if otp==key:
            return redirect(url_for('register'))
        else:
            msg="OTP wrong!"
            
    return render_template('web/reg_otp.html',msg=msg)

def generateKeys(prk,pbk):
    (publicKey, privateKey) = rsa.newkeys(1024)
    with open('keys/'+pbk, 'wb') as p:
        p.write(publicKey.save_pkcs1('PEM'))
    with open('keys/'+prk, 'wb') as p:
        p.write(privateKey.save_pkcs1('PEM'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    msg=""
    act=""
    aadhar = session['aadhar']
    mobile = session['mobile']
    print(aadhar)
    
    mycursor = mydb.cursor()
    mycursor.execute("SELECT max(id)+1 FROM hc_patient")
    maxid = mycursor.fetchone()[0]
    if maxid is None:
        maxid=1
    if request.method=='POST':
        name=request.form['name']
        gender=request.form['gender']
        dob=request.form['dob']
        
        address=request.form['address']
        email=request.form['email']
        uname=request.form['uname']
        pass1=request.form['pass']
        
        prk="prk_"+str(maxid)+".pem"
        pbk="pbk_"+str(maxid)+".pem"
        generateKeys(prk,pbk)

        key=randint(10000,99999)
        mycursor.execute("SELECT count(*) FROM hc_patient where uname=%s",(uname,))
        cnt = mycursor.fetchone()[0]
        
        if cnt==0:
            sql = "INSERT INTO hc_patient(id,name,gender,dob,mobile,email,address,uname,pass,aadhar,ukey) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,%s)"
            val = (maxid,name,gender,dob,mobile,email,address,uname,pass1,aadhar,key)
            mycursor.execute(sql, val)
            mydb.commit()            
            print(mycursor.rowcount, "Registered Success")
            act="sucess"

            message="Patient ID:"+uname+", Name:"+name+", Password:"+pass1+", Hash Key:"+str(key)
            #if mycursor.rowcount==1:
            url="http://iotcloud.co.in/testmail/testmail1.php?email="+email+"&message="+message
            webbrowser.open_new(url)
            return redirect(url_for('index',act=act))
        else:
            msg='Already Exist'
    return render_template('web/register.html',msg=msg)


@app.route('/reg_hos', methods=['GET', 'POST'])
def reg_hos():
    msg=""
    act=request.args.get("act")
    
    
    mycursor = mydb.cursor()
    mycursor.execute("SELECT max(id)+1 FROM hc_hospital")
    maxid = mycursor.fetchone()[0]
    if maxid is None:
        maxid=1
    if request.method=='POST':
        name=request.form['name']
        mobile=request.form['mobile']
        address=request.form['address']
        email=request.form['email']
        uname=request.form['uname']
        pass1=request.form['pass']
        
     

        mycursor.execute("SELECT count(*) FROM hc_hospital where uname=%s",(uname,))
        cnt = mycursor.fetchone()[0]
        
        if cnt==0:
            sql = "INSERT INTO hc_hospital(id,name,mobile,email,address,uname,pass,status) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
            val = (maxid,name,mobile,email,address,uname,pass1,'0')
            mycursor.execute(sql, val)
            mydb.commit()            
            print(mycursor.rowcount, "Registered Success")
            act="success"
            if mycursor.rowcount==1:
                return redirect(url_for('login_hos',act=act))
        else:
            msg='Already Exist'
    return render_template('web/reg_hos.html',msg=msg,act=act)

@app.route('/reg_lab', methods=['GET', 'POST'])
def reg_lab():
    msg=""
    act=""
    
    mycursor = mydb.cursor()
    mycursor.execute("SELECT max(id)+1 FROM hc_lab")
    maxid = mycursor.fetchone()[0]
    if maxid is None:
        maxid=1
    if request.method=='POST':
        name=request.form['name']
        mobile=request.form['mobile']
        address=request.form['address']
        email=request.form['email']
        uname=request.form['uname']
        pass1=request.form['pass']
        
     

        mycursor.execute("SELECT count(*) FROM hc_lab where uname=%s",(uname,))
        cnt = mycursor.fetchone()[0]
        
        if cnt==0:
            sql = "INSERT INTO hc_lab(id,name,mobile,email,address,uname,pass,status) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
            val = (maxid,name,mobile,email,address,uname,pass1,'0')
            mycursor.execute(sql, val)
            mydb.commit()            
            print(mycursor.rowcount, "Registered Success")
            act="success"
            if mycursor.rowcount==1:
                return redirect(url_for('login_lab',act=act))
        else:
            msg='Already Exist'
    return render_template('web/reg_lab.html',msg=msg)

@app.route('/login_doc', methods=['GET', 'POST'])
def login_doc():
    msg=""

    
    if request.method=='POST':
        uname=request.form['uname']
        pwd=request.form['pass']
        cursor = mydb.cursor()
        cursor.execute('SELECT * FROM hc_doctor WHERE uname = %s AND pass = %s', (uname, pwd))
        account = cursor.fetchone()
        if account:
            session['username'] = uname

            
            return redirect(url_for('doc_home'))
        else:
            msg = 'Incorrect username/password!'
    return render_template('web/login_doc.html',msg=msg)

@app.route('/login_staff', methods=['GET', 'POST'])
def login_staff():
    msg=""

    
    if request.method=='POST':
        uname=request.form['uname']
        pwd=request.form['pass']
        cursor = mydb.cursor()
        cursor.execute('SELECT * FROM hc_staff WHERE uname = %s AND pass = %s', (uname, pwd))
        account = cursor.fetchone()
        if account:
            session['username'] = uname

            
            return redirect(url_for('staff_home'))
        else:
            msg = 'Incorrect username/password!'
    return render_template('web/login_staff.html',msg=msg)


@app.route('/reg_doc', methods=['GET', 'POST'])
def reg_doc():
    msg=""

    mycursor = mydb.cursor()
    mycursor.execute("SELECT max(id)+1 FROM doctor")
    maxid = mycursor.fetchone()[0]
    if maxid is None:
        maxid=1
    if request.method=='POST':
        name=request.form['name']
        
        mobile=request.form['mobile']
        email=request.form['email']
        uname=request.form['uname']
        pass1=request.form['pass']
        cursor = mydb.cursor()

        
        sql = "INSERT INTO hc_doctor(id,name,mobile,email,uname,pass,hname) VALUES (%s, %s, %s, %s, %s, %s, %s)"
        val = (maxid,name,mobile,email,uname,pass1,hname)
        cursor.execute(sql, val)
        mydb.commit()            
        print(cursor.rowcount, "Registered Success")
        result="sucess"
        if cursor.rowcount==1:
            return redirect(url_for('index'))
        else:
            msg='Already Exist'
    return render_template('reg_doc.html',msg=msg)

def loadKeys(pbk,prk):
    with open('keys/'+pbk, 'rb') as p:
        publicKey = rsa.PublicKey.load_pkcs1(p.read())
    with open('keys/'+prk, 'rb') as p:
        privateKey = rsa.PrivateKey.load_pkcs1(p.read())
    return privateKey, publicKey


def encrypt(message, key):
    return rsa.encrypt(message.encode('ascii'), key)

def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        return False



@app.route('/pat_home', methods=['GET', 'POST'])
def pat_home():
    msg=""
    if 'username' in session:
        uname = session['username']
    st=""
    cursor = mydb.cursor()
    cursor.execute('SELECT * FROM hc_patient WHERE uname = %s', (uname, ))
    data = cursor.fetchone()

    if request.method=='POST':
        st="1"
        
    return render_template('pat_home.html',msg=msg, data=data,st=st)

@app.route('/pat_block', methods=['GET', 'POST'])
def pat_block():
    msg=""
    if 'username' in session:
        uname = session['username']
    st=""
    cursor = mydb.cursor()
    cursor.execute('SELECT * FROM hc_patient WHERE uname = %s', (uname, ))
    data = cursor.fetchone()
    key=data[11]
    if request.method=='POST':
        st="1"
        
    return render_template('pat_block.html',msg=msg, data=data,st=st,uname=uname,key=key)

@app.route('/process', methods=['GET', 'POST'])
def process():
    msg=""
    h1=randint(60,120)
    b1=randint(90,120)
    b2=randint(60,80)
    t=randint(32,34)

    hb=str(h1)
    bp=str(b1)+"/"+str(b2)
    temp=str(t)
    
    return render_template('process.html',msg=msg, hb=hb,bp=bp,temp=temp)

@app.route('/pat_shared', methods=['GET', 'POST'])
def pat_shared():
    msg=""
    uname=""
    if 'username' in session:
        uname = session['username']
    act=request.args.get("act")
    cursor = mydb.cursor()
    cursor.execute('SELECT * FROM hc_patient WHERE uname = %s', (uname, ))
    data = cursor.fetchone()

    cursor.execute('SELECT * FROM hc_share WHERE uname = %s', (uname, ))
    data1 = cursor.fetchall()

    cursor.execute('SELECT * FROM hc_share2 WHERE uname = %s', (uname, ))
    data2 = cursor.fetchall()

    cursor.execute('SELECT * FROM hc_share3 WHERE uname = %s', (uname, ))
    data3 = cursor.fetchall()

    cursor.execute('SELECT * FROM hc_share4 WHERE uname = %s', (uname, ))
    data4 = cursor.fetchall()

    cursor.execute('SELECT * FROM hc_share5 WHERE uname = %s', (uname, ))
    data5 = cursor.fetchall()

    cursor.execute('SELECT * FROM hc_share6 WHERE uname = %s', (uname, ))
    data6 = cursor.fetchall()

    if act=="del":
        did=request.args.get("did")
        cursor.execute("delete from hc_share where id=%s",(did,))
        mydb.commit()
        return redirect(url_for('pat_shared'))

    if act=="del2":
        did2=request.args.get("did2")
        cursor.execute("delete from hc_share2 where id=%s",(did2,))
        mydb.commit()
        return redirect(url_for('pat_shared'))
        
        
    return render_template('pat_shared.html',msg=msg, data=data,data1=data1,data2=data2,data3=data3,data4=data4,data5=data5,data6=data6)


@app.route('/pat_add', methods=['GET', 'POST'])
def pat_add():
    msg=""
    if 'username' in session:
        uname = session['username']
    
    cursor = mydb.cursor()
    cursor.execute('SELECT * FROM hc_patient WHERE uname = %s', (uname, ))
    data = cursor.fetchone()
    pid=data[0]

    prk="prk_"+str(pid)+".pem"
    pbk="pbk_"+str(pid)+".pem"
    publicKey, privateKey =loadKeys(pbk,prk)
        

    if request.method=='POST':
        name=request.form['name']
        
        name=request.form['name']
        detail=request.form['detail']
        
       
        now = datetime.datetime.now()
        rdate=now.strftime("%d-%m-%Y")

        cursor.execute("SELECT max(id)+1 FROM hc_data")
        maxid = cursor.fetchone()[0]
        if maxid is None:
            maxid=1

        #######
        
        enmsg=encrypt(detail, privateKey)
        #print(enmsg)

        #ciphertext=b'\x0fz\xaa3\xbe\xa1YT>|\xcb\x06zf\x02\xad\x86\xb7\x10^\xf7\xf8\xa1\xfb\xe1\xd6\x06"\x8bD\xb9E\xfd/$\xb5n&\xd0\xbd1H\x9f\xc2\xdf\xd5[\xfe\xa3\xbfwc\xfe\x1d\xe8:\xc8M\xcd\xe9\x000R&\xfe\x8a\xa3\xde\x9a\x82\xeb\x1e\x8e\xcc\xcb\xc1\xd0\xc6\x18\x15\xee)\xed\x13Y\xff\x96\xcb\x8b5\xb5\x90\t\xa8 \xd2E\xfb\xf3\xa2\x08\x07\xbc\xe1\x92\x8cH\xa7\x16\r\xe0\xa1{=\xdd\x87\xed\xc6\\7b(\xcc\x12\xb3\xe6@c'

        #decmsg=decrypt(ciphertext, publicKey)
        #print(decmsg)
        ####
            
            
        sql = "INSERT INTO hc_data(id,uname,name,detail,rdate) VALUES (%s, %s, %s, %s, %s)"
        val = (maxid,uname,name,detail,rdate)
        cursor.execute(sql, val)
        mydb.commit()            
        print(cursor.rowcount, "Registered Success")
        result="sucess"
        #bcdata="Patient:"+patid+"-Health Data:"+detail
        if cursor.rowcount==1:
            return redirect(url_for('pat_add'))
       
    cursor.execute('SELECT * FROM hc_data WHERE uname = %s', (uname, ))
    data1 = cursor.fetchall()

    for dd1 in data1:
        encdata=dd1[3]
        decmsg=decrypt(encdata, publicKey)
        print(decmsg)
        
        
    return render_template('pat_add.html',msg=msg, data=data,data1=data1)



@app.route('/pat_upload', methods=['GET', 'POST'])
def pat_upload():
    msg=""
    act=""
    bcdata=""
    if 'username' in session:
        uname = session['username']
    cursor = mydb.cursor()
    cursor.execute('SELECT * FROM hc_patient WHERE uname = %s', (uname, ))
    data = cursor.fetchone()

    cursor.execute('SELECT * FROM hc_files WHERE uname = %s', (uname, ))
    data1 = cursor.fetchall() 

    ff=open("bc.txt","r")
    bc=ff.read()
    ff.close()
    
    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
        
    if request.method=='POST':
        file_content=request.form['details']
        

        mycursor = mydb.cursor()
        mycursor.execute("SELECT max(id)+1 FROM hc_files")
        maxid = mycursor.fetchone()[0]
        if maxid is None:
            maxid=1

        


        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        
        file_type = file.content_type
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file:
            fname = "F"+str(maxid)+file.filename
            filename = secure_filename(fname)
            
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        

        
        ##encryption
        password_provided = uname # This is input in the form of a string
        password = password_provided.encode() # Convert to type bytes
        salt = b'salt_' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))

        input_file = 'static/upload/'+fname
        output_file = 'static/encrypted/E'+fname
        with open(input_file, 'rb') as f:
            data = f.read()

        fernet = Fernet(key)
        encrypted = fernet.encrypt(data)

        with open(output_file, 'wb') as f:
            f.write(encrypted)
            
        
        
        ##store
        sql = "INSERT INTO hc_files(id,uname,file_type,file_content,upload_file,rdate) VALUES (%s, %s, %s, %s, %s, %s)"
        val = (maxid,uname,file_type,file_content,filename,rdate)
        mycursor.execute(sql,val)
        mydb.commit()
        
        msg="Uploaded success.."
        act="yes"
        bcdata="Patient:"+uname+"-Upload File:"+filename
        #return redirect(url_for('pat_upload',fname=filename))
            
        
            
    return render_template('pat_upload.html',msg=msg, data=data,data1=data1,act=act,bc=bc,bcdata=bcdata)


@app.route('/pat_share', methods=['GET', 'POST'])
def pat_share():
    msg=""

    bcdata=""
    ff=open("bc.txt","r")
    bc=ff.read()
    ff.close()
    
    act=request.args.get("act")
    view=request.args.get("view")
    hid=request.args.get("hid")
    fname=request.args.get("fname")
    fid=request.args.get("fid")

    doctor=request.args.get("doctor")
    staff=request.args.get("staff")
    
    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
    
    if 'username' in session:
        uname = session['username']
    cursor = mydb.cursor()
    cursor.execute('SELECT * FROM hc_patient WHERE uname = %s', (uname, ))
    data = cursor.fetchone()

    cursor.execute('SELECT * FROM hc_hospital')
    data1 = cursor.fetchall()

    cursor.execute('SELECT * FROM hc_doctor where hname=%s',(hid,))
    data2 = cursor.fetchall()

    cursor.execute('SELECT * FROM hc_staff where hname=%s',(hid,))
    data3 = cursor.fetchall()

    if act=="ok":
        print("s")
        if view=="nurse":

            cursor.execute('SELECT count(*) FROM hc_share2 where staff=%s and fid=%s',(staff,fid))
            cnt = cursor.fetchone()[0]

            if cnt==0:
            
                cursor.execute("SELECT max(id)+1 FROM hc_share2")
                maxid = cursor.fetchone()[0]
                if maxid is None:
                    maxid=1
                sql = "INSERT INTO hc_share2(id,uname,fid,fname,staff,rdate) VALUES (%s, %s, %s, %s, %s, %s)"
                val = (maxid,uname,fid,fname,staff,rdate)
                cursor.execute(sql,val)
                mydb.commit()

                msg="Shared Success"
                act="yes"
                bcdata="Patient:"+uname+"-Share File:"+fname+", Staff:"+staff

                
        elif view=="doctor":

            cursor.execute('SELECT count(*) FROM hc_share where doctor=%s and fid=%s',(doctor,fid))
            cnt = cursor.fetchone()[0]

            if cnt==0:
            
                cursor.execute("SELECT max(id)+1 FROM hc_share")
                maxid = cursor.fetchone()[0]
                if maxid is None:
                    maxid=1
                sql = "INSERT INTO hc_share(id,uname,fid,fname,doctor,rdate) VALUES (%s, %s, %s, %s, %s, %s)"
                val = (maxid,uname,fid,fname,doctor,rdate)
                cursor.execute(sql,val)
                mydb.commit()

                msg="Shared Success"
                act="yes"
                bcdata="Patient:"+uname+"-Share File:"+fname+", Doctor:"+doctor
                

    return render_template('pat_share.html',msg=msg, data=data,data1=data1,data2=data2,data3=data3,hid=hid,fname=fname,fid=fid,view=view,act=act,bcdata=bcdata,bc=bc)


@app.route('/pat_share1', methods=['GET', 'POST'])
def pat_share1():
    msg=""
    msg2=""

    bcdata=""
    ff=open("bc.txt","r")
    bc=ff.read()
    ff.close()

    
    act=request.args.get("act")
    view=request.args.get("view")
    hid=request.args.get("hid")
   

    doctor=request.args.get("doctor")
    staff=request.args.get("staff")
    
    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
    
    if 'username' in session:
        uname = session['username']
    cursor = mydb.cursor()
    cursor.execute('SELECT * FROM hc_patient WHERE uname = %s', (uname, ))
    data = cursor.fetchone()

    cursor.execute('SELECT * FROM hc_hospital')
    data1 = cursor.fetchall()

    cursor.execute('SELECT * FROM hc_doctor where hname=%s',(hid,))
    data2 = cursor.fetchall()

    cursor.execute('SELECT * FROM hc_staff where hname=%s',(hid,))
    data3 = cursor.fetchall()

    if act=="ok":
        print("s")
        if view=="nurse":

            cursor.execute('SELECT count(*) FROM hc_share4 where staff=%s and uname=%s',(staff,uname))
            cnt = cursor.fetchone()[0]

            if cnt==0:
            
                cursor.execute("SELECT max(id)+1 FROM hc_share4")
                maxid = cursor.fetchone()[0]
                if maxid is None:
                    maxid=1
                sql = "INSERT INTO hc_share4(id,uname,staff,rdate) VALUES (%s, %s, %s, %s)"
                val = (maxid,uname,staff,rdate)
                cursor.execute(sql,val)
                mydb.commit()

                msg="Shared Success"
        elif view=="doctor":

            cursor.execute('SELECT count(*) FROM hc_share3 where doctor=%s and uname=%s',(doctor,uname))
            cnt = cursor.fetchone()[0]

            if cnt==0:
            
                cursor.execute("SELECT max(id)+1 FROM hc_share3")
                maxid = cursor.fetchone()[0]
                if maxid is None:
                    maxid=1
                sql = "INSERT INTO hc_share3(id,uname,doctor,rdate) VALUES (%s, %s, %s, %s)"
                val = (maxid,uname,doctor,rdate)
                cursor.execute(sql,val)
                mydb.commit()

                msg2="Shared Success"

                

    return render_template('pat_share1.html',msg=msg,msg2=msg2,data=data,data1=data1,data2=data2,data3=data3,hid=hid,view=view)


@app.route('/pat_share2', methods=['GET', 'POST'])
def pat_share2():
    msg=""
    msg2=""
    act=request.args.get("act")
    view=request.args.get("view")
    hid=request.args.get("hid")
   

    doctor=request.args.get("doctor")
    staff=request.args.get("staff")
    
    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
    
    if 'username' in session:
        uname = session['username']
    cursor = mydb.cursor()
    cursor.execute('SELECT * FROM hc_patient WHERE uname = %s', (uname, ))
    data = cursor.fetchone()

    cursor.execute('SELECT * FROM hc_hospital')
    data1 = cursor.fetchall()

    cursor.execute('SELECT * FROM hc_doctor where hname=%s',(hid,))
    data2 = cursor.fetchall()

    cursor.execute('SELECT * FROM hc_staff where hname=%s',(hid,))
    data3 = cursor.fetchall()

    if act=="ok":
        print("s")
        if view=="nurse":

            cursor.execute('SELECT count(*) FROM hc_share6 where staff=%s and uname=%s',(staff,uname))
            cnt = cursor.fetchone()[0]

            if cnt==0:
            
                cursor.execute("SELECT max(id)+1 FROM hc_share6")
                maxid = cursor.fetchone()[0]
                if maxid is None:
                    maxid=1
                sql = "INSERT INTO hc_share6(id,uname,staff,rdate) VALUES (%s, %s, %s, %s)"
                val = (maxid,uname,staff,rdate)
                cursor.execute(sql,val)
                mydb.commit()

                msg="Shared Success"
        elif view=="doctor":

            cursor.execute('SELECT count(*) FROM hc_share5 where doctor=%s and uname=%s',(doctor,uname))
            cnt = cursor.fetchone()[0]

            if cnt==0:
            
                cursor.execute("SELECT max(id)+1 FROM hc_share5")
                maxid = cursor.fetchone()[0]
                if maxid is None:
                    maxid=1
                sql = "INSERT INTO hc_share5(id,uname,doctor,rdate) VALUES (%s, %s, %s, %s)"
                val = (maxid,uname,doctor,rdate)
                cursor.execute(sql,val)
                mydb.commit()

                msg2="Shared Success"

                

    return render_template('pat_share2.html',msg=msg,msg2=msg2,data=data,data1=data1,data2=data2,data3=data3,hid=hid,view=view)


@app.route('/lab_upload', methods=['GET', 'POST'])
def lab_upload():
    msg=""
    if 'username' in session:
        uname = session['username']
    act=""
    cursor = mydb.cursor()
    cursor.execute('SELECT * FROM hc_lab WHERE uname = %s', (uname, ))
    data = cursor.fetchone()

    cursor.execute('SELECT * FROM hc_files WHERE upload_by = %s', (uname, ))
    data1 = cursor.fetchall() 

    bcdata=""
    ff=open("bc.txt","r")
    bc=ff.read()
    ff.close()

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
        
    if request.method=='POST':
        patid=request.form['patid']
        file_content=request.form['details']
        

        mycursor = mydb.cursor()
        mycursor.execute("SELECT max(id)+1 FROM hc_files")
        maxid = mycursor.fetchone()[0]
        if maxid is None:
            maxid=1

        


        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        
        file_type = file.content_type
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file:
            fname = "F"+str(maxid)+file.filename
            filename = secure_filename(fname)
            
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        

        
        ##encryption
        password_provided = patid # This is input in the form of a string
        password = password_provided.encode() # Convert to type bytes
        salt = b'salt_' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))

        input_file = 'static/upload/'+fname
        output_file = 'static/encrypted/E'+fname
        with open(input_file, 'rb') as f:
            data = f.read()

        fernet = Fernet(key)
        encrypted = fernet.encrypt(data)

        with open(output_file, 'wb') as f:
            f.write(encrypted)
            
        
        
        ##store
        sql = "INSERT INTO hc_files(id,uname,file_type,file_content,upload_file,rdate,upload_by) VALUES (%s, %s, %s, %s, %s, %s,%s)"
        val = (maxid,patid,file_type,file_content,filename,rdate,uname)
        mycursor.execute(sql,val)
        mydb.commit()
        act="yes"
        msg="Uploaded success.."
        bcdata="Patient:"+patid+"-Upload File:"+filename+", Lab:"+uname
        
        #return redirect(url_for('lab_upload',fname=filename))
            
        
            
    return render_template('lab_upload.html',msg=msg, data=data,data1=data1,bc=bc,bcdata=bcdata,act=act)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    msg=""
    act=request.args.get("act")
    if 'username' in session:
        uname = session['username']
    
    cursor = mydb.cursor()
    cursor.execute('SELECT * FROM hc_hospital')
    data = cursor.fetchall()

    cursor.execute('SELECT * FROM hc_lab')
    data2 = cursor.fetchall()

    if act=="yes":
        hid=request.args.get("hid")
        cursor.execute("update hc_hospital set status=1 where id=%s",(hid,))
        mydb.commit()

        return redirect(url_for('admin'))

    if act=="lab":
        lid=request.args.get("lid")
        cursor.execute("update hc_lab set status=1 where id=%s",(lid,))
        mydb.commit()

        return redirect(url_for('admin'))

        
    return render_template('admin.html',msg=msg, data=data, data2=data2,act=act)



@app.route('/sugg', methods=['GET', 'POST'])
def sugg():
    msg=""
    if 'username' in session:
        uname = session['username']
    
    cursor = mydb.cursor()
    
    cursor.execute('SELECT * FROM suggest WHERE pid = %s', (uname, ))
    data = cursor.fetchall()
        
    return render_template('sugg.html',msg=msg, data=data)


@app.route('/hos_home', methods=['GET', 'POST'])
def hos_home():
    msg=""
    act=request.args.get("act")
    em=request.args.get("em")
    mess=request.args.get("mess")
    if 'username' in session:
        uname = session['username']
    
    mycursor = mydb.cursor()
    mycursor.execute('SELECT * FROM hc_hospital where uname=%s',(uname,))
    data1 = mycursor.fetchone()
    name=data1[1]

    
    mycursor.execute("SELECT max(id)+1 FROM hc_doctor")
    maxid = mycursor.fetchone()[0]
    if maxid is None:
        maxid=1
    did="DT"+str(maxid)
    
    if request.method=='POST':
        docid=request.form['docid']
        name=request.form['name']
        mobile=request.form['mobile']
        email=request.form['email']
        
        now = datetime.datetime.now()
        rdate=now.strftime("%d-%m-%Y")
        pass1="1234"
        
        sql = "INSERT INTO hc_doctor(id,name,mobile,email,uname,pass,hname) VALUES (%s, %s, %s, %s, %s, %s,%s)"
        val = (maxid,name,mobile,email,docid,pass1,uname)
        mycursor.execute(sql, val)
        mydb.commit()            
        print(mycursor.rowcount, "Registered Success")
        msg="Register success"
        mess="Doctor: "+name+", Doctor ID:"+docid+", Password:"+pass1
        return redirect(url_for('hos_home',act='add',em=email,mess=mess))
        
    mycursor.execute('SELECT * FROM hc_doctor where hname=%s',(uname,))
    data = mycursor.fetchall()

    if act=="del":
        did=request.args.get("did")
        mycursor.execute("delete from hc_doctor where id=%s",(did,))
        mydb.commit()
        return redirect(url_for('hos_home'))
        
    return render_template('hos_home.html',msg=msg, name=name, did=did, data1=data1, data=data, act=act, em=em, mess=mess)

@app.route('/hos_staff', methods=['GET', 'POST'])
def hos_staff():
    msg=""
    act=request.args.get("act")
    em=request.args.get("em")
    mess=request.args.get("mess")
    if 'username' in session:
        uname = session['username']
    
    mycursor = mydb.cursor()
    mycursor.execute('SELECT * FROM hc_hospital where uname=%s',(uname,))
    data1 = mycursor.fetchone()
    name=data1[1]

    
    mycursor.execute("SELECT max(id)+1 FROM hc_staff")
    maxid = mycursor.fetchone()[0]
    if maxid is None:
        maxid=1
    sid="ST"+str(maxid)
    
    if request.method=='POST':
        staffid=request.form['staffid']
        name=request.form['name']
        mobile=request.form['mobile']
        email=request.form['email']
        
        now = datetime.datetime.now()
        rdate=now.strftime("%d-%m-%Y")
        pass1="1234"
        
        sql = "INSERT INTO hc_staff(id,name,mobile,email,uname,pass,hname) VALUES (%s, %s, %s, %s, %s, %s,%s)"
        val = (maxid,name,mobile,email,staffid,pass1,uname)
        mycursor.execute(sql, val)
        mydb.commit()            
        print(mycursor.rowcount, "Registered Success")
        msg="Register success"
        mess="Staff: "+name+", Staff ID:"+staffid+", Password:"+pass1
        return redirect(url_for('hos_staff',act='add',em=email,mess=mess))
        
    mycursor.execute('SELECT * FROM hc_staff where hname=%s',(uname,))
    data = mycursor.fetchall()

    if act=="del":
        did=request.args.get("did")
        mycursor.execute("delete from hc_staff where id=%s",(did,))
        mydb.commit()
        return redirect(url_for('hos_staff'))
        
    return render_template('hos_staff.html',msg=msg, name=name, sid=sid, data1=data1, data=data, act=act, em=em, mess=mess)


@app.route('/doc_home', methods=['GET', 'POST'])
def doc_home():
    msg=""
    pid=request.args.get("pid")
    act=request.args.get("act")

    
    if 'username' in session:
        uname = session['username']
    data2=[]
    data3=[]
    data4=[]
    data22=[]
    cursor = mydb.cursor()
    cursor.execute('SELECT * FROM hc_doctor WHERE uname = %s', (uname, ))
    data = cursor.fetchone()

    st=""
    hh=""
    dm=""
    x=0

    
    if request.method=='POST':
        patid=request.form['patid']

        cursor.execute('SELECT count(*) FROM hc_patient WHERE uname = %s', (patid, ))
        cnt = cursor.fetchone()[0]
        if cnt>0:
            st="1"

            
            cursor.execute('SELECT count(*) FROM hc_share3 WHERE uname=%s && doctor = %s', (patid, uname))
            cnt2 = cursor.fetchone()[0]
            if cnt2>0:
                x+=1
                hh="1"

            cursor.execute('SELECT count(*) FROM hc_share WHERE uname=%s && doctor = %s', (patid, uname))
            cnt3 = cursor.fetchone()[0]
            if cnt3>0:
                x+=1

            cursor.execute('SELECT count(*) FROM hc_share5 WHERE uname=%s && doctor = %s', (patid, uname))
            cnt3 = cursor.fetchone()[0]
            if cnt3>0:
                x+=1
                dm="1"
            ##demogrp
            cursor.execute('SELECT * FROM hc_patient WHERE uname = %s', (patid, ))
            data21 = cursor.fetchone()

            result = hashlib.md5(data21[1].encode())
            key1=result.hexdigest()
            data22.append(key1)

            result = hashlib.md5(data21[2].encode())
            key1=result.hexdigest()
            data22.append(key1)

            result = hashlib.md5(data21[3].encode())
            key1=result.hexdigest()
            data22.append(key1)

            result = hashlib.md5(data21[6].encode())
            key1=result.hexdigest()
            data22.append(key1)

            result = hashlib.md5(str(data21[4]).encode())
            key1=result.hexdigest()
            data22.append(key1)

            result = hashlib.md5(data21[5].encode())
            key1=result.hexdigest()
            data22.append(key1)

            result = hashlib.md5(data21[9].encode())
            key1=result.hexdigest()
            data22.append(key1)
            
            ##files
            cursor.execute('SELECT * FROM hc_patient WHERE uname = %s', (patid, ))
            data2 = cursor.fetchone()

            cursor.execute('SELECT * FROM hc_files WHERE uname = %s', (patid, ))
            data31 = cursor.fetchall()
            for r31 in data31:
                dt=[]
                dt.append(r31[4])
                res=""
                cursor.execute('SELECT count(*) FROM hc_share WHERE fid=%s && uname = %s && doctor=%s', (r31[0],patid, uname))
                dd = cursor.fetchone()[0]
                if dd>0:
                    res="1"
                else:
                    res="2"
                dt.append(res)
                dt.append(r31[1])
                data3.append(dt)


            ##health data
            cursor.execute('SELECT * FROM hc_data WHERE uname = %s', (patid, ))
            data41 = cursor.fetchall()
            for r41 in data41:
                dt=[]
                dt.append(r41[2])
                dt.append(r41[3])

                result = hashlib.md5(r41[3].encode())
                key=result.hexdigest()
                dt.append(key)
                
                data4.append(dt)
            if x==0:
                msg="No Information!"
        
        else:
            msg="Patient ID wrong!"

    
  
    
    return render_template('doc_home.html',msg=msg, data=data,st=st,data2=data2,data3=data3,data4=data4,hh=hh,dm=dm,data22=data22)

@app.route('/doc_decrypt', methods=['GET', 'POST'])
def doc_decrypt():
    msg=""
    pid=request.args.get("patid")
    act=request.args.get("act")
    fname=request.args.get("fname")

    bcdata=""
    ff=open("bc.txt","r")
    bc=ff.read()
    ff.close()

    
    if 'username' in session:
        uname = session['username']
    data2=[]
    data3=[]
    data4=[]
    data22=[]
    cursor = mydb.cursor()
    cursor.execute('SELECT * FROM hc_doctor WHERE uname = %s', (uname, ))
    data = cursor.fetchone()


    if act=="yes":
        ###Decrypt 
        '''password_provided = pid # This is input in the form of a string
        password = password_provided.encode() # Convert to type bytes
        salt = b'salt_' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        input_file = 'static/encrypted/E'+fname
        output_file = 'static/decrypted/'+fname
        with open(input_file, 'rb') as f:
            data = f.read()

        fernet = Fernet(key)
        encrypted = fernet.decrypt(data)

        with open(output_file, 'wb') as f:
            f.write(encrypted)'''
        
            
        bcdata="Patient:"+str(pid)+"-Decrypt and View File:"+fname+", Doctor:"+uname
    if act=="no":

        bcdata="Patient:"+str(pid)+"-Unauthorized access file:"+fname+", Doctor:"+uname

    print(bcdata)    
    return render_template('doc_decrypt.html',msg=msg, data=data,act=act,pid=pid,bc=bc,bcdata=bcdata,fname=fname)


@app.route('/staff_decrypt', methods=['GET', 'POST'])
def staff_decrypt():
    msg=""
    pid=request.args.get("patid")
    act=request.args.get("act")
    fname=request.args.get("fname")

    bcdata=""
    ff=open("bc.txt","r")
    bc=ff.read()
    ff.close()

    
    if 'username' in session:
        uname = session['username']
    data2=[]
    data3=[]
    data4=[]
    data22=[]
    cursor = mydb.cursor()
    cursor.execute('SELECT * FROM hc_staff WHERE uname = %s', (uname, ))
    data = cursor.fetchone()


    if act=="yes":
        ###Decrypt 
        '''password_provided = pid # This is input in the form of a string
        password = password_provided.encode() # Convert to type bytes
        salt = b'salt_' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        input_file = 'static/encrypted/E'+fname
        output_file = 'static/decrypted/'+fname
        with open(input_file, 'rb') as f:
            data = f.read()

        fernet = Fernet(key)
        encrypted = fernet.decrypt(data)

        with open(output_file, 'wb') as f:
            f.write(encrypted)'''
        
            
        bcdata="Patient:"+str(pid)+"-Decrypt and View File:"+fname+", Staff:"+uname
    if act=="no":

        bcdata="Patient:"+str(pid)+"-Unauthorized access file:"+fname+", Staff:"+uname

    print(bcdata)    
    return render_template('staff_decrypt.html',msg=msg, data=data,act=act,pid=pid,bc=bc,bcdata=bcdata,fname=fname)


@app.route('/staff_home', methods=['GET', 'POST'])
def staff_home():
    msg=""
    if 'username' in session:
        uname = session['username']
    data2=[]
    data3=[]
    data4=[]
    data22=[]
    cursor = mydb.cursor()
    cursor.execute('SELECT * FROM hc_staff WHERE uname = %s', (uname, ))
    data = cursor.fetchone()

    st=""
    hh=""
    dm=""
    x=0
    if request.method=='POST':
        patid=request.form['patid']

        cursor.execute('SELECT count(*) FROM hc_patient WHERE uname = %s', (patid, ))
        cnt = cursor.fetchone()[0]
        if cnt>0:
            st="1"

            
            cursor.execute('SELECT count(*) FROM hc_share4 WHERE uname=%s && staff = %s', (patid, uname))
            cnt2 = cursor.fetchone()[0]
            if cnt2>0:
                x+=1
                hh="1"

            cursor.execute('SELECT count(*) FROM hc_share2 WHERE uname=%s && staff = %s', (patid, uname))
            cnt3 = cursor.fetchone()[0]
            if cnt3>0:
                x+=1

            cursor.execute('SELECT count(*) FROM hc_share6 WHERE uname=%s && staff = %s', (patid, uname))
            cnt3 = cursor.fetchone()[0]
            if cnt3>0:
                x+=1
                dm="1"
            ##demogrp
            cursor.execute('SELECT * FROM hc_patient WHERE uname = %s', (patid, ))
            data21 = cursor.fetchone()

            result = hashlib.md5(data21[1].encode())
            key1=result.hexdigest()
            data22.append(key1)

            result = hashlib.md5(data21[2].encode())
            key1=result.hexdigest()
            data22.append(key1)

            result = hashlib.md5(data21[3].encode())
            key1=result.hexdigest()
            data22.append(key1)

            result = hashlib.md5(data21[6].encode())
            key1=result.hexdigest()
            data22.append(key1)

            result = hashlib.md5(str(data21[4]).encode())
            key1=result.hexdigest()
            data22.append(key1)

            result = hashlib.md5(data21[5].encode())
            key1=result.hexdigest()
            data22.append(key1)

            result = hashlib.md5(data21[9].encode())
            key1=result.hexdigest()
            data22.append(key1)
            
            ##files
            cursor.execute('SELECT * FROM hc_patient WHERE uname = %s', (patid, ))
            data2 = cursor.fetchone()

            cursor.execute('SELECT * FROM hc_files WHERE uname = %s', (patid, ))
            data31 = cursor.fetchall()
            for r31 in data31:
                dt=[]
                dt.append(r31[4])
                res=""
                cursor.execute('SELECT count(*) FROM hc_share2 WHERE fid=%s && uname = %s && staff=%s', (r31[0],patid, uname))
                dd = cursor.fetchone()[0]
                if dd>0:
                    res="1"
                else:
                    res="2"
                dt.append(res)
                dt.append(r31[1])
                data3.append(dt)


            ##health data
            cursor.execute('SELECT * FROM hc_data WHERE uname = %s', (patid, ))
            data41 = cursor.fetchall()
            for r41 in data41:
                dt=[]
                dt.append(r41[2])
                dt.append(r41[3])

                result = hashlib.md5(r41[3].encode())
                key=result.hexdigest()
                dt.append(key)
                
                data4.append(dt)
            if x==0:
                msg="No Information!"
        
        else:
            msg="Patient ID wrong!"
  
    
    return render_template('staff_home.html',msg=msg, data=data,st=st,data2=data2,data3=data3,data4=data4,hh=hh,dm=dm,data22=data22)

@app.route('/doc_sugg', methods=['GET', 'POST'])
def doc_sugg():
    msg=""
    
    if 'username' in session:
        uname = session['username']
    
    if request.method=='GET':
        pid = request.args.get('pid')
    if request.method=='POST':
        pid=request.form['pid']
        sugg=request.form['suggestion']
        pres=request.form['prescription']
        cursor = mydb.cursor()

        now = datetime.datetime.now()
        rdate=now.strftime("%d-%m-%Y")
            
        mycursor = mydb.cursor()
        mycursor.execute("SELECT max(id)+1 FROM suggest")
        maxid = mycursor.fetchone()[0]
        if maxid is None:
            maxid=1
        sql = "INSERT INTO suggest(id,pid,suggestion,prescription,rdate) VALUES (%s, %s, %s, %s, %s)"
        val = (maxid,pid,sugg,pres,rdate)
        cursor.execute(sql, val)
        mydb.commit()            
        print(cursor.rowcount, "Registered Success")
        msg="Register success"
        
    return render_template('doc_sugg.html',msg=msg, pid=pid)



@app.route('/logout')
def logout():
    # remove the username from the session if it is there
    session.pop('username', None)
    return redirect(url_for('index'))



if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)


