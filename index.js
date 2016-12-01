const express = require('express');
const app = express();
const bodyParser = require('body-parser');// 解析body字段模块
const morgan = require('morgan'); // 命令行log显示
const mongoose = require('mongoose');
const passport = require('passport');// 用户认证模块passport
const Strategy = require('passport-http-bearer').Strategy;// token验证模块
const routes = require('./routes');
const config = require('./config');

let port = process.env.PORT || 8080;

app.use(passport.initialize());// 初始化passport模块
app.use(morgan('dev'));// 命令行中显示程序运行日志,便于bug调试
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json()); // 调用bodyParser模块以便程序正确解析body传入值

routes(app);

mongoose.Promise = global.Promise;
mongoose.connect(config.database); // 连接数据库

app.listen(port, () => {
  console.log('listening on port : ' + port);
})
