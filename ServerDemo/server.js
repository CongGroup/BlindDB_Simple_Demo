var express = require('express');
var app = express();
var redis = require('redis');
var RDS_PORT = 6379;
var RDS_HOST = 'localhost';
var client = redis.createClient(RDS_PORT, RDS_HOST);
var sp = '\n--------------------------------------------------'
client.on('ready', function() {
    console.log('Ready' + sp);

    app.get('/g/:skey' , function (req, res) {
        console.log("Get data from Redis");
        console.log("Key: " + req.params.skey);
        client.get(req.params.skey, function (err, reply) {

            if (err)  {
                console.error(err);
            }
            console.log("Value = " + reply + sp);
            res.set("Access-Control-Allow-Origin", "*");
            res.json({"Value": reply});


        });
    });


    app.post('/put/:skey/:size', function (req, res) {
        var skey = req.params.skey;
        var size = req.params.size;
        console.log("Store key value pair.");
        console.log("Key: " + skey);
        console.log("Value: " + size);
        client.set(skey, size, function (err, reply) {
            console.log(reply.toString() + sp);
        });
        res.set("Access-Control-Allow-Origin", "*");
    });

    var server = app.listen(8081, function () {

        var host = "127.0.0.1";
        var port = server.address().port;


        //console.log('The server is listening at http://%s:%s', host, port);
    });
});