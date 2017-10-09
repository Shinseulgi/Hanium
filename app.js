/**
 * Module dependencies.
 */
//basic setting///////////////////////////////////////////////////////////////////////////// 
var MongoClient = require('mongodb').MongoClient
, assert = require('assert');

//Connection URL
var url = 'mongodb://localhost:27017/test';

var express = require('express')
  , routes = require('./routes')
  , user = require('./routes/user')
  , http = require('http')
  , path = require('path')
  , fs = require('fs')
  , async = require('async');

var app = express();

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');
app.use(express.bodyParser());

var session = require('express-session');

//Login Page///////////////////////////////////////////////////////////////////////////// 
app.get('/', function(req, res) {
    MongoClient.connect(url, function(err, db) {
        if(err) throw err;
            db.collection('splitLogCollection').find().toArray(function(err, data) {
                res.render('loginpage', {
                    data: data
                })
            });
    });
});
 
function authenticateUser(userID, password, callback){
    MongoClient.connect(url, function(err, db) {
        if(err) throw err;
        var coll = db.collection('UserCollection');
        
        coll.findOne({id: userID, pw:password}, function(err, user){
            callback(err, user);
        });
    });
}
 
app.post('/', function(req, res) {
    var db = req.db;
    
    var userID = req.body.id;
    var userPW = req.body.pw;
    LoginID=userID;
    //console.log(userID);
    
    authenticateUser(userID, userPW, function(err, user) {
        if(user){
            console.log("login");
            res.render('uploadpage', {
                id: userID
            });
            
        }
        else {
            console.log("login fail");
            res.redirect('/');
            }
    });
});
var LoginID;
var GETTODAY;
//Upload Page/////////////////////////////////////////////////////////////////////////////	
app.get('/upload', function(req, res) {
    res.render('uploadpage', {
        title: 'File Upload'        	
    });
});

app.post('/file-upload', function(req, res) {
	var date=new Date();
	var year=date.getFullYear();
	var month=date.getMonth()+1;
	var day=date.getDate();
	if((day+"").length<2)
		day="0"+day;
	GETTODAY=year+"-"+month+"-"+day;
	
	var tmp_path = req.files.thumbnail.path; 
	var target_path = './' + req.files.thumbnail.name; 
	var name4file2read = './' + req.files.thumbnail.name; 
	fs.rename(tmp_path, target_path, function(err) { 
		if (err) throw err; 
		fs.unlink(tmp_path, function() { 
			if (err) throw err; 
			fs.readFile(name4file2read, function(err, data) {
			    if(err) throw err;
			    var array = data.toString().split("\n");
			    MongoClient.connect(url, function(err, db) {
			        if(err) throw err;
			        //input raw log
			        var coll = db.collection('Rawlogtest');
			        var batch = coll.initializeOrderedBulkOp();
			        for(i in array){
			          var newKey = {id: LoginID, inputdate:GETTODAY, log:array[i]};
			          console.log(newKey);
			          batch.insert(newKey);
			        }
			        batch.execute(function(err, result) { db.close();});
			    });
			});
			res.redirect('/uploadsplitlog');
		}); 
	}); 
});

app.get('/uploadsplitlog', function(req, res) {
	MongoClient.connect(url, function(err, db) {
        if(err) throw err;
        //input split log 
        var coll2split=db.collection('splitlogtest');
        var batch2split = coll2split.initializeOrderedBulkOp();
        db.collection('Rawlogtest').find({id: LoginID, inputdate:GETTODAY}).toArray(function(err, data) {
        	for(var i=0;i<data.length;i++){
        	   var log2split=data[i].log;
        	   var strToken = log2split.split(" ");
               var strToken2= log2split.split(strToken[6]);
               var strToken3= strToken2[1].split(strToken[strToken.length-3]);
               var pageQuery = strToken3[0];
               var hackfilter = pageQuery.includes("'","\"","--","/*","*/","(",")","<",">","=","union","insert","select","drop","update","and","or","If","Join");
               var htmlfilter =  pageQuery.includes("<script","<img","<div","<embed","<iframe");
               var hackStr="";
               var hackCnt=0;
               if(hackfilter==1){
            	   if(hackCnt>0){
            		   hackStr += "+";
            	   }
            	   hackStr += "inj";
            	   hackCnt++;
               }
               if(pageQuery.includes("Id","id")) {
                    if(hackCnt > 0)
                    	hackStr += "+";
                    if(pageQuery.includes("sessionId")) {            //2. Broken Authentication and Session Management
                     	hackStr += "basm";
                     	hackCnt++;
                    }
                    else {                                          //4. Sensitive Data Exposure
                     	hackStr += "sde";
                     	hackCnt++;
                    }
               }
               if(pageQuery.includes("secure")) {
                    if(pageQuery.includes("=")) {
                    	if(hackCnt > 0)
                            hackStr += "+";
                        hackStr += "sde";
                        hackCnt++;
                   }
               } 
               if(htmlfilter==1){
            	   if(hackCnt>0){
            		   hackStr += "+";
            	   }
            	   hackStr += "xss";
            	   hackCnt++;
               }
               if(hackCnt==0)                                 //no hacking
                    hackStr="none";
               //hacking code add, param !!!!!!!!!!!!!!!!!!!!!!!!
        	   var newKey2split = {id: LoginID, inputdate:GETTODAY, date: strToken[0], time: strToken[1], srcIp:  strToken[2], dstIp:  strToken[4], proto:  strToken[5], csmethod: strToken[6], page: strToken3[0], param: "-", status: strToken[strToken.length-3], hackType: hackStr};
		       console.log(newKey2split);
        	   batch2split.insert(newKey2split);
        	}
           batch2split.execute(function(err, result){ db.close();});
        });
    });
	res.redirect('/uploadranklog');
});

app.get('/uploadranklog', function(req, res) {
	MongoClient.connect(url, function(err, db) {
        if(err) throw err;
        var coll2rank = db.collection('ranktest');
        var batch2rank = coll2rank.initializeOrderedBulkOp();
        db.collection('splitlogtest').aggregate(
        	 {$group: {_id: {$toLower:'$hackType'}, count: { $sum: 1 }}}
        , function(err, result) {
            if(err) {
                db.close();
                throw err;
            }
            console.log(result);
            //batch2rank.insert(result);
        });
         //batch2rank.execute(function(err, result) { db.close();});
    });
	res.redirect('/analysis');
});

//Analysis Page/////////////////////////////////////////////////////////////////////////////
app.get('/analysis', function(req, res) {
    res.render('analysispage', {
        title: 'Analysis',
        	id: LoginID
    });
});

app.get('/pre_analysis', function(req, res) {
    res.render('pre_analysis', {
        title: 'pre_analysis',
        	id: LoginID
    });
});

app.get('/analysis_eventnumber', function(req, res) {
	   MongoClient.connect(url, function(err,db){
	         if(err) throw err;
	         
	         db.collection('timeRankCollection').find().toArray(function(err, data) {
	            res.render('as_eventnumberpage', {
	               data: data,
	               id: LoginID
	               })
	            });
	         });
	});

app.get('/analysis_ip', function(req, res) {
	MongoClient.connect(url, function(err,db){
		if(err) throw err;
		    db.collection('srcRankCollection').find().toArray(function(err, data) {
	            res.render('as_ippage', {
	               data: data,
	               id: LoginID
	            })
	        });
	    });
	});

app.get('/analysis_page', function(req, res) {
	   MongoClient.connect(url, function(err,db){
	         if(err) throw err;
	         db.collection('pageRankCollection').find().toArray(function(err, data) {
	            res.render('as_pagepage', {
	               data: data,
	               id: LoginID
	               })
	               });
	   });
	});

app.get('/analysis_proto', function(req, res) {
	   MongoClient.connect(url, function(err,db){
	         if(err) throw err;
	         db.collection('protoRankCollection').find().toArray(function(err, data) {
	            res.render('as_protopage', {
	               data: data,
	               id: LoginID
	               })
	               });
	   });
	});

app.get('/analysis_status', function(req, res) {
	   MongoClient.connect(url, function(err,db){
	         if(err) throw err;
	         db.collection('statusRankCollection').find().toArray(function(err, data) {
	            res.render('as_statuspage', {
	               data: data,
	               id: LoginID
	               })
	               });
	   });
	});

var injcnt, basmcnt, xsscnt, sdecnt;
app.get('/hackanalysis', function(req, res) {
   MongoClient.connect(url, function(err,db){
         if(err) throw err;
         var injLogs = db.collection("splitLogCollection").find({'hack_Type':{$regex : ".*inj.*"}});
         var basmLogs = db.collection("splitLogCollection").find({'hack_Type':{$regex : ".*basm.*"}});
         var xssLogs = db.collection("splitLogCollection").find({'hack_Type':{$regex : ".*xss.*"}});
         var sdeLogs = db.collection("splitLogCollection").find({'hack_Type':{$regex : ".*sde.*"}});
         injLogs.count(function(error, cnt) {
            injcnt=cnt;
         });
         basmLogs.count(function(error, cnt) {
            basmcnt=cnt;
         });
         xssLogs.count(function(error, cnt) {
            xsscnt=cnt;
         });
         sdeLogs.count(function(error, cnt) {
            sdecnt=cnt;
         });
         var solution;
         db.collection("hackingCollection").find({type:"inj"}).forEach(function(obj) {
               solution = obj.solution
             });
         db.collection('splitLogCollection').find({'hack_Type':{$regex : ".*inj.*"}},{"_id":false,"hack_Type":false}).toArray(function(err, data) {
            res.render('hackanalysispage', {
               data : data, solutionText : solution, injcnt:injcnt, basmcnt:basmcnt, xsscnt:xsscnt,  sdecnt:sdecnt, id: LoginID
               });
         });
   });
});

app.get('/hackanalysis_basm', function(req, res) {
   MongoClient.connect(url, function(err,db){
         if(err) throw err;
         var solution;
         db.collection("hackingCollection").find({type:"basm"}).forEach(function(obj) {
               solution = obj.solution
             });
         db.collection('splitLogCollection').find({'hack_Type':{$regex : ".*basm.*"}},{"_id":false,"hack_Type":false}).toArray(function(err, data) {
            res.render('hackanalysispage', {
               data : data, solutionText : solution, injcnt:injcnt, basmcnt:basmcnt, xsscnt:xsscnt,  sdecnt:sdecnt, id: LoginID
               });
         });
   });
});

app.get('/hackanalysis_xss', function(req, res) {
   MongoClient.connect(url, function(err,db){
         if(err) throw err;
         var solution;
         db.collection("hackingCollection").find({type:"xss"}).forEach(function(obj) {
               solution = obj.solution
             });
         db.collection('splitLogCollection').find({'hack_Type':{$regex : ".*xss.*"}},{"_id":false,"hack_Type":false}).toArray(function(err, data) {
            res.render('hackanalysispage', {
               data : data, solutionText : solution, injcnt:injcnt, basmcnt:basmcnt, xsscnt:xsscnt,  sdecnt:sdecnt, id: LoginID
               });
         });
   });
});

app.get('/hackanalysis_sde', function(req, res) {
   MongoClient.connect(url, function(err,db){
         if(err) throw err;
         var solution;
         db.collection("hackingCollection").find({type:"sde"}).forEach(function(obj) {
               solution = obj.solution
             });
         db.collection('splitLogCollection').find({'hack_Type':{$regex : ".*sde.*"}},{"_id":false,"hack_Type":false}).toArray(function(err, data) {
            res.render('hackanalysispage', {
               data : data, solutionText : solution, injcnt:injcnt, basmcnt:basmcnt, xsscnt:xsscnt,  sdecnt:sdecnt, id: LoginID
               });
         });
   });
});

//Join Page/////////////////////////////////////////////////////////////////////////////
app.get('/join', function(req, res) {
	MongoClient.connect(url, function(err,db){
		if(err) throw err;
			db.collection('UserCollection').find({},{'id':true}).toArray(function(err, data) {
				res.render('joinpage', {
					data: data
				});
			});
		});
});

app.post('/join', function(req, res) {
    // Set our internal DB variable
    var db = req.db;

    // Get our form values. These rely on the "name" attributes
    var userName = req.body.name;
    var userID = req.body.id;
    var userPW = req.body.pw;
    var userEmail = req.body.email;
    var userBirth = req.body.birth;
    
    // Set our collection
    MongoClient.connect(url, function(err,db){
    	if(err) throw err;
    	var collection = db.collection('UserCollection');

        // Submit to the DB
        collection.insert({
            "name" : userName,
            "id" : userID,
            "pw" : userPW,
            "email" : userEmail,
            "birth" : userBirth
        }, function (err, doc) {
            if (err) {
                // If it failed, return error
                res.send("There was a problem adding the information to the database.");
            }
            else {
                // And forward to success page
                res.redirect("");
            }
        });
    });
});

//Find Page/////////////////////////////////////////////////////////////////////////////
app.get('/find_id', function(req, res) {
	MongoClient.connect(url, function(err,db){
		if(err) throw err;
			db.collection('UserCollection').find({},{'id':true,'name':true,'pw':true,'birth':true}).toArray(function(err, data) {
				res.render('findIDpage', {
					data: data
				});
			});
		});
});

app.get('/find_pw', function(req, res) {
	MongoClient.connect(url, function(err,db){
		if(err) throw err;
			db.collection('UserCollection').find({},{'id':true,'name':true,'pw':true,'birth':true}).toArray(function(err, data) {
				res.render('findPWpage', {
					data: data
				});
			});
		});
});

//Edit Page/////////////////////////////////////////////////////////////////////////////
app.get('/editinfo', function(req, res) {
    res.render('editinfopage', {
        title: 'Edit My Info'
    });
});

//Server Start                                                                        
app.listen(3000); 