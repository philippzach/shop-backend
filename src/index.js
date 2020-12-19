// let's go!
const cookieParser = require('cookie-parser')
require('dotenv').config({ path: 'variables.env' });
const createServer = require('./createServer');
const bodyParser = require("body-parser");
const db = require('./db');
const jwt = require('jsonwebtoken');
//const stripe = require('stripe')(process.env.STRIPE_SECRET);

const server = createServer();

server.use(bodyParser.urlencoded({ extended: false }));
server.use(bodyParser.json());

// Use express middleware to handle cookies (JWT)
server.express.use(cookieParser())
// TODO Use express middleware to populate current users

//1. decode the JWT so we can get the user ID on each request
server.express.use((req, res, next)=> {
  const {token} = req.cookies;
if(token) {
  const {userId} = jwt.verify(token, 'shhhhh')
  //put the user id on to the request or further request to access
  req.userId= userId
}
next()
})

//2. Create a middleware that populates the user on each request
server.express.use(async (req, res, next) => {
  // if they aren't logged in, skip this
  if (!req.userId) return next();
  const user = await db.query.user(
    { where: { id: req.userId } },
    '{ id, permissions, email, name }'
  );
  req.user = user;
  next();
});

/* server.post('/create-checkout-session', async (req, res) => {
  const session = await stripe.checkout.sessions.create({
    payment_method_types: ['card'],
    line_items: req.body,
    mode: 'payment',
    success_url: `${process.env.FRONTEND_URL}?success=true`,
    cancel_url: `${process.env.FRONTEND_URL}?canceled=true`,
  });
  res.json({ id: session.id });
}); */

server.start(
 /*  {
    cors: {
      credentials: true,
      origin: process.env.FRONTEND_URL
    }
  }, */
  message => {
    console.log(
      `Server is now runnin on port http://localhost:${message.port}`
    );
  }
);
