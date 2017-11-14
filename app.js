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
    console.log(LoginID);
    
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
var INIT;
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
			    MongoClient.connect(url,{
				    server: {
				        socketOptions: {
				            keepAlive: 300000,
				            connectTimeoutMS: 30000
				        }
				    },
				    replset: {
				        socketOptions: {
				            keepAlive: 300000,
				            connectTimeoutMS: 30000
				        }
				    }
				}, function(err, db) {
			        if(err) throw err;
			        //input raw log
			        var coll = db.collection('originLogCollection');
			        var batch = coll.initializeOrderedBulkOp();
			        for(i in array){
			          var newKey = {'id':LoginID,'inputdate':GETTODAY,log:array[i]};
			          console.log(newKey);
			          batch.insert(newKey);
			        }
			        batch.execute(function(err, result) { db.close();});
			    });
			});
		}); 
	}); 
	res.redirect('/uploadsplitlog');
});

app.get('/uploadsplitlog', function(req, res) {
	MongoClient.connect(url,{
	    server: {
	        socketOptions: {
	            keepAlive: 300000,
	            connectTimeoutMS: 30000
	        }
	    },
	    replset: {
	        socketOptions: {
	            keepAlive: 300000,
	            connectTimeoutMS: 30000
	        }
	    }
	}, function(err, db) {
        if(err) throw err;
        //input split log 
        var coll2split=db.collection('splitLogCollection');
        var batch2split = coll2split.initializeOrderedBulkOp();
        db.collection('originLogCollection').find({'id':LoginID,'inputdate':GETTODAY}).toArray(function(err, data) {
        	for(var i=0;i<(data.length)-1;i++){
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
                   if(strToken[1]+"".length<6)
                	   var timeitem="0"+strToken[1];
                   else
                	   var timeitem=strToken[1];
            	   var newKey2split = {'id':LoginID,'inputdate':GETTODAY,date: strToken[0], time: timeitem, srcIp:  strToken[2], dstIp:  strToken[4], proto:  strToken[5], csmethod: strToken[6], page: strToken3[0], param: "-", status: strToken[strToken.length-3], hackType: hackStr};
            	   console.log(newKey2split);
            	   batch2split.insert(newKey2split);
            	}
               batch2split.execute(function(err, result){ db.close();});
        	   
        });
    });
	res.redirect('/uploadranklog');
});

app.get('/uploadranklog', function(req, res) {
	INIT=0;
	res.redirect('/analysis');	
});
//Analysis Page/////////////////////////////////////////////////////////////////////////////
app.get('/analysis', function(req, res) {
	if( INIT==0){
		MongoClient.connect(url,function(err, db) {
	        if(err) throw err;
	        var coll2pagerank = db.collection('pageRankCollection');
	        db.collection('splitLogCollection').aggregate(
	        	 {$group: {_id: {page:'$page',id: '$id', inputdate: '$inputdate'}, count: { $sum: 1 } }}
	        , function(err, result) {
	            if(err) {
	                db.close();
	                throw err;
	            }
	            console.log(result);
	            coll2pagerank.insert(result);
	        });
	        //batch2rank.execute(function(err, result) { db.close();});
	    });
		MongoClient.connect(url,function(err, db) {
	        if(err) throw err;
	        var coll2pagerank = db.collection('protoRankCollection');
	        db.collection('splitLogCollection').aggregate(
	        	 {$group: {_id: {proto:'$proto', id: '$id', inputdate: '$inputdate'},count: { $sum: 1 } }}
	        , function(err, result) {
	            if(err) {
	                db.close();
	                throw err;
	            }
	            console.log(result);
	            coll2pagerank.insert(result);
	        });
	        //batch2rank.execute(function(err, result) { db.close();});
	    });
		MongoClient.connect(url,function(err, db) {
	        if(err) throw err;
	        var coll2pagerank = db.collection('srcRankCollection');
	        db.collection('splitLogCollection').aggregate(
	        	 {$group: {_id: {ip:'$srcIp',id: '$id', inputdate:'$inputdate'},count: { $sum: 1 } }}
	        , function(err, result) {
	            if(err) {
	                db.close();
	                throw err;
	            }
	            console.log(result);
	            coll2pagerank.insert(result);
	        });
	        //batch2rank.execute(function(err, result) { db.close();});
	    });
		MongoClient.connect(url, function(err, db) {
	        if(err) throw err;
	        var coll2pagerank = db.collection('statusRankCollection');
	        db.collection('splitLogCollection').aggregate(
	        	 {$group: {_id: {status:'$status',id: '$id', inputdate: '$inputdate'}, count: { $sum: 1 } }}
	        , function(err, result) {
	            if(err) {
	                db.close();
	                throw err;
	            }
	            console.log(result);
	            coll2pagerank.insert(result);
	        });
	        //batch2rank.execute(function(err, result) { db.close();});
	    });
		MongoClient.connect(url, function(err, db) {
	        if(err) throw err;
	        var coll2pagerank = db.collection('timeRankCollection');
	        db.collection("splitLogCollection").aggregate([
	            { $group : { _id: {date: "$date" , hour: {$arrayElemAt: [{ $split: ["$time",":"] },0]}}, 
	               "count" : {$sum : 1}}
	            }
	           ,{$sort : {_id:1}}
	         ]).toArray(function(err, result) {
	             assert.equal(err, null);
	             console.log(result);
	             coll2pagerank.insert(result);
	         });
	        //batch2rank.execute(function(err, result) { db.close();});
	    });
		INIT=1;
		}
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

var eventArr=[];
app.get('/analysis_eventnumber', function(req, res) {
	    MongoClient.connect(url, function(err,db){
	        if(err) throw err;
	        db.collection('timeRankCollection').find().toArray(function(err, data) {
	           eventArr[0]=Array.apply(null, new Array(25)).map(Number.prototype.valueOf,0);
	           eventArr[1]=Array.apply(null, new Array(25)).map(Number.prototype.valueOf,0);
	           eventArr[2]=Array.apply(null, new Array(25)).map(Number.prototype.valueOf,0);
	           eventArr[0][0]="2015-10-26";
	           eventArr[1][0]="2015-10-27";
	           eventArr[2][0]="2015-10-28";
	           for(var i=0;i<(data.length);i++){
	        	   if(data[i]._id.date.indexOf('26')!=-1){
	        		   eventArr[0][parseInt(data[i]._id.hour)+1]=data[i].count;
	        	   }
	        	   else if(data[i]._id.date.indexOf('27')!=-1){
	        		   eventArr[1][parseInt(data[i]._id.hour)+1]=data[i].count;
	        	   }
	        	   else{
	        		   eventArr[2][parseInt(data[i]._id.hour)+1]=data[i].count;
	        	   }
	           }     
	           console.log(eventArr);
	           
         res.render('as_eventnumberpage', {
               data: data, eventArr : eventArr, id: LoginID 
              })
           });
	    }); 
});

app.get('/analysis_ip', function(req, res) {
	MongoClient.connect(url, function(err,db){
		if(err) throw err;
		    db.collection('srcRankCollection').find({'_id.id':LoginID,'_id.inputdate':GETTODAY}).sort({"count":-1}).toArray(function(err, data) {
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
	         db.collection('pageRankCollection').find({'_id.id':LoginID,'_id.inputdate':GETTODAY}).sort({"count":-1}).toArray(function(err, data) {
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
	         db.collection('protoRankCollection').find({'_id.id':LoginID,'_id.inputdate':GETTODAY}).sort({"_id.count":-1}).toArray(function(err, data) {
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
	         db.collection('statusRankCollection').find({'_id.id':LoginID,'_id.inputdate':GETTODAY}).sort({"count":-1}).toArray(function(err, data) {
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
         var injLogs = db.collection("splitLogCollection").find({'id':LoginID,'inputdate':GETTODAY,'hackType':{$regex : ".*inj.*"}});
         var basmLogs = db.collection("splitLogCollection").find({'id':LoginID,'inputdate':GETTODAY,'hackType':{$regex : ".*basm.*"}});
         var xssLogs = db.collection("splitLogCollection").find({'id':LoginID,'inputdate':GETTODAY,'hackType':{$regex : ".*xss.*"}});
         var sdeLogs = db.collection("splitLogCollection").find({'id':LoginID,'inputdate':GETTODAY,'hackType':{$regex : ".*sde.*"}});
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
         db.collection('splitLogCollection').find({'id':LoginID,'inputdate':GETTODAY,'hackType':{$regex : ".*inj.*"}},{"_id":false,"hackType":false}).toArray(function(err, data) {
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
         db.collection('splitLogCollection').find({'id':LoginID,'inputdate':GETTODAY,'hackType':{$regex : ".*basm.*"}},{"_id":false,"hackType":false}).toArray(function(err, data) {
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
         db.collection('splitLogCollection').find({'id':LoginID,'inputdate':GETTODAY,'hackType':{$regex : ".*xss.*"}},{"_id":false,"hackType":false}).toArray(function(err, data) {
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
         db.collection('splitLogCollection').find({'id':LoginID,'inputdate':GETTODAY,'hackType':{$regex : ".*sde.*"}},{"_id":false,"hackType":false}).toArray(function(err, data) {
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

function userInfo(userID, callback) {
   MongoClient.connect(url, function(err, db) {
        if(err) throw err;
        var coll = db.collection('UserCollection');
        
        coll.findOne({id: userID}, function(err, user){
            callback(err, user);
        });
    });
}

app.get('/editinfo', function(req, res) {
   userInfo(LoginID, function(err, user) {
      if(user){
         res.render('editinfopage', {
            id: LoginID,
            name: user.name,
            pw: user.pw,
            email: user.email,
            birth: user.birth,
            user: user
         });
         //console.log(user);
      }else {
         console.log("failed");
      }
   })
});

app.post('/editinfo', function(req, res) {
    // Set our internal DB variable
    var db = req.db;

    // Get our form values. These rely on the "name" attributes
    var userName = req.body.name;
    var userID = req.body.id;
    var userPW = req.body.pw;
    var newPW1 = req.body.new_pw1;
    var userEmail = req.body.email;
    var userBirth = req.body.birth;
    
    MongoClient.connect(url, function(err,db){
       if(err) throw err;
       var collection = db.collection('UserCollection');

       userInfo(LoginID, function(err, user) {
           collection.update({
              "id": LoginID, "pw": userPW},{$set: {
                 "birth": userBirth,
                 "email": userEmail,
                 "pw": newPW1
              }
              }, function(err, doc) {
                 if (err) {
                        res.send("There was a problem adding the information to the database.");
                    }
                    else {
                        res.render('uploadpage', {
                           id: LoginID
                        });
                    }
              });
        });
    });
});

//Server Start                                                                        
app.listen(3000); 