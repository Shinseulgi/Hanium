var MongoClient = require('mongodb').MongoClient
, assert = require('assert');

//Connection URL
var url = 'mongodb://localhost:27017/test';

var express = require('express')
  , routes = require('./routes')
  , user = require('./routes/user')
  , http = require('http')
  , path = require('path')
  , fs = require('fs');

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
    LoginID = userID;
    //console.log(userID);
    
    authenticateUser(userID, userPW, function(err, user) {
        if(user){
            console.log("login");
            //res.redirect('/upload');
            res.render('uploadpage', {
                id: userID
            });
            LoginID = userID;
            
        }
        else {
            console.log("login fail");
            res.redirect('/');
            }
    });
});
var LoginID;
//Upload Page/////////////////////////////////////////////////////////////////////////////	
app.get('/upload', function(req, res) {
    res.render('uploadpage', {
        title: 'Upload'
    });
});

app.post('/file-upload', function(req, res) { 
	// get the temporary location of the file 
	var tmp_path = req.files.thumbnail.path; 
	// set where the file should actually exists - in this case it is in the "images" directory 
	var target_path = './' + req.files.thumbnail.name; 
	// move the file from the temporary location to the intended location 
	fs.rename(tmp_path, target_path, function(err) { 
		if (err) throw err; 
	// delete the temporary file, so that the explicitly set temporary upload dir does not get filled with unwanted files 
		fs.unlink(tmp_path, function() { 
			if (err) throw err; 
			res.redirect('/analysis');
		}); 
	}); 
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

var eventArr=[];
app.get('/analysis_eventnumber', function(req, res) {
   MongoClient.connect(url, function(err,db){
         if(err) throw err;
         db.collection('timeRankCollection').find().toArray(function(err, data) {
            for(var i=0;i<(data.length/24);i++){
                  eventArr[i]=new Array();
                  eventArr[i][0]=data[(i*24)]._id.date;
                  for(var j=0;j<24;j++){
                     eventArr[i][j+1]=data[(i*24)+j].count;
                  }
               }
            
          res.render('as_eventnumberpage', {
               data : data, eventArr : eventArr, id: LoginID
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