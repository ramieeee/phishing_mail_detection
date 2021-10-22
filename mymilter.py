from __future__ import print_function
import feature_extraction as fe # our own feature module

# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2001 Business Management Systems, Inc.
# This code is under GPL.  See COPYING for details.

import sys
import os
try:
  from io import BytesIO
except:
  from StringIO import StringIO as BytesIO
import mime
import Milter
import tempfile
from time import strftime
# import tensorflow as tf
import numpy as np
import re
import requests
import pickle
# from sklearn.externals import joblib
import joblib
from sklearn.metrics import accuracy_score
from sklearn import ensemble
from sklearn.multioutput import MultiOutputClassifier
import warnings
warnings.filterwarnings('ignore')

#import syslog

#syslog.openlog('milter')

class myMilter(Milter.Milter):
  "Milter to replace attachments poisonous to Windows with a WARNING message."

  def log(self,*msg):
    print("%s [%d]" % (strftime('%Y%b%d %H:%M:%S'),self.id),end=None)
    for i in msg: print(i,end=None)
    print()

  def __init__(self):
    self.tempname = None
    self.mailfrom = None
    self.fp = None
    self.bodysize = 0
    self.id = Milter.uniqueID()
    self.user = None
    self.isspam = False
    self.subject = ""

  # multiple messages can be received on a single connection
  # envfrom (MAIL FROM in the SMTP protocol) seems to mark the start
  # of each message.
  @Milter.symlist('{auth_authen}')
  @Milter.noreply
  def envfrom(self,f,*str):
    "start of MAIL transaction"
    self.fp = BytesIO()
    self.tempname = None
    self.mailfrom = f
    self.bodysize = 0
    self.user = self.getsymval('{auth_authen}')
    self.auth_type = self.getsymval('{auth_type}')
    if self.user:
      self.log("user",self.user,"sent mail from",f,str)
    else:
      self.log("mail from",f,str)
    return Milter.CONTINUE

  def envrcpt(self,to,*str):
    # mail to MAILER-DAEMON is generally spam that bounced
    if to.startswith('<MAILER-DAEMON@'):
      self.log('DISCARD: RCPT TO:',to,str)
      return Milter.DISCARD
    self.log("rcpt to",to,str)
    return Milter.CONTINUE

  def header(self,name,val):
    lname = name.lower()
    if lname == 'subject':
      self.subject = val

    # log selected headers
    if lname in ('subject','x-mailer'):
      self.log('%s: %s' % (name,val))
    if self.fp:
      self.fp.write(("%s: %s\n" % (name,val)).encode())	# add header to buffer
    return Milter.CONTINUE

  def eoh(self):
    if not self.fp: return Milter.TEMPFAIL	# not seen by envfrom
    self.fp.write(b'\n')
    self.fp.seek(0)
    # copy headers to a temp file for scanning the body
    headers = self.fp.getvalue()
    self.fp.close()
    self.tempname = fname = tempfile.mktemp(".defang")
    self.fp = open(fname,"w+b")
    self.fp.write(headers)	# IOError (e.g. disk full) causes TEMPFAIL
    return Milter.CONTINUE

  def body(self,chunk):		# copy body to temp file
    header = {'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36'}
    if self.fp:
      self.fp.write(chunk)	# IOError causes TEMPFAIL in milter
      self.bodysize += len(chunk)

    # url extraction with decoding
    text = chunk.decode('utf-8').strip()
    urls = re.findall(r'(https?:\/\/[^\s]+)', text)
    print('******')
    print('url list: %s' %urls)
    print('******')

      # url check(get request 200 -> ok, else: error)
    for url in urls:
#     try
      res = requests.get(url, headers=header, timeout=2)
      print("-> %s: Status %s\n" %(url, res))
        
        # feature extraction
      feature = fe.FeatureExtraction(url)
      feature_score = np.array([feature.run_process()])
      print('Feature_score')
      print(feature_score)
      print()

        # call model and integrate feature_score
      model = joblib.load('./phishing_model.pkl')
      prediction = model.predict(feature_score)
      print('Prediction result: %d\n\n' %int(prediction))
      if int(prediction) == -1:
        self.isspam = True
        #break
#      except:
#        pass
    print('******')
    
    return Milter.CONTINUE

  def _headerChange(self,msg,name,value):
    if value:	# add header
      self.addheader(name,value)
    else:	# delete all headers with name
      h = msg.getheaders(name)
      cnt = len(h)
      for i in range(cnt,0,-1):
        self.chgheader(name,i-1,'')

  def eom(self):
    if not self.fp: return Milter.ACCEPT
    if self.isspam == True:
      self.addheader('subject', '[PHISHING]'+self.subject, idx=-1)
    self.fp.seek(0)
    msg = mime.message_from_file(self.fp)
    msg.headerchange = self._headerChange
    if not mime.defang(msg,self.tempname):
      os.remove(self.tempname)
      self.tempname = None	# prevent re-removal
      self.log("eom")
      return Milter.ACCEPT	# no suspicious attachments
    self.log("Temp file:",self.tempname)
    self.tempname = None	# prevent removal of original message copy
    # copy defanged message to a temp file 
    with tempfile.TemporaryFile() as out:
      msg.dump(out)
      out.seek(0)
      msg = mime.message_from_file(out)
      fp = BytesIO(msg.as_bytes().split(b'\n\n',1)[1])
      while 1:
        buf = fp.read(8192)
        if len(buf) == 0: break
        self.replacebody(buf)	# feed modified message to sendmail
      return Milter.ACCEPT	# ACCEPT modified message
    return Milter.TEMPFAIL

  def close(self):
    sys.stdout.flush()		# make log messages visible
    if self.tempname:
      os.remove(self.tempname)	# remove in case session aborted
    if self.fp:
      self.fp.close()
    return Milter.CONTINUE

  def abort(self):
    self.log("abort after %d body chars" % self.bodysize)
    return Milter.CONTINUE

if __name__ == "__main__":
  #tempfile.tempdir = "/var/log/milter"
  #socketname = "/var/log/milter/pythonsock"
  socketname = os.getenv("HOME") + "/pythonsock"
  Milter.factory = myMilter
  Milter.set_flags(Milter.CHGBODY + Milter.CHGHDRS + Milter.ADDHDRS)
  print("""To use this with sendmail, add the following to sendmail.cf:

O InputMailFilters=pythonfilter
Xpythonfilter,        S=local:%s

See the sendmail README for libmilter.
sample  milter startup""" % socketname)
  sys.stdout.flush()
  Milter.runmilter("pythonfilter",socketname,240)
  print("sample milter shutdown")
