module.exports = (app) => {
  app.get('/', (req, res) => {
    res.json({ message: 'hello index!'});
  });

  app.use('/api', require('./users')); // 在所有users路由前加/api
};
