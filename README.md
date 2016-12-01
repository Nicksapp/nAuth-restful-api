## Node.js+Mongoose的RestfulApi的用户token权限验证

### 安装
`git clone https://github.com/Nicksapp/nAuth-restful-api.git`

### 运行
`npm install`

具体数据库配置信息在config.js中设置

### 整体构架
开发前先进行我们设计的构想

* 路由设计
    * POST /api/signup: 用户注册
    * POST /api/user/accesstoken: 账号验证,获取token
    * GET /api/user/user_info: 获得用户信息,需验证

* user 模型设计
    * name : 用户名
    * password: 密码
    * token: 验证相关token