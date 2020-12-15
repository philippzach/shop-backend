const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const {randomBytes} = require('crypto')
const {promisify} = require('util')
const {transport, makeANiceEmail} = require('../mail');
const { hasPermission } = require('../utils');

const Mutations = {
  async addAdminRights(parent, args, ctx, info) {
    //Get the user
    const update = await ctx.db.mutation.updateUser({
      data: {  permissions: { set: ['ADMIN', 'USER'] }},
      where: {email: args.email}
    }, info);
    return update
  },
  async createItem(parent, args, ctx, info) {
    // TODO Check if they are logged in
    if(!ctx.request.userId) {
      throw new Error('You mus be logged in to do that')
    }
   // console.log(ctx.db);
    const item = await ctx.db.mutation.createItem(
      {
        data: {
          //this how to create a realtionship between the item and the user
          user: {
            connect: {
              id: ctx.request.userId
            },
          },
          ...args,
        }
      },
      info
    );

    return item;
  },
  updateItem(parent, args, ctx, info) {
    //first take a copy of the updates
    const updates = {...args};
    //remove the ID from the updates
    delete updates.id;
    //run the update method
    return ctx.db.mutation.updateItem({
      data: updates,
      where: {
        id: args.id
      }
    }, info)
  },
  async deleteItem(parent, args, ctx, info) {
    const where = { id : args.id};
    //1. find item
    const item = await ctx.db.query.item({where}, `{id title user {id}}`)
    //2. check if they own that item, or have permissions
    //TODO
    const ownsItem = item.user.id === ctx.request.user.Id;
    const hasPermissions = ctx.request.user.permissions.some(permission => ['ADMIN', 'ITEMDELETE'].includes(permission))
    if(!ownsItem || !hasPermissions) {
      throw new Error('You dont have permission to delete this item')
    }
    
    //3. Delete it!!!
   return ctx.db.mutation.deleteItem({where}, info)
  },
  async signup(parent, args, ctx, info) {
    //lowercase email
    args.email = args.email.toLowerCase();
    //hash their password
    const password = await bcrypt.hash(args.password, 10);
    //creat the user in the database
    const user = await ctx.db.mutation.createUser({
      data: {
        ...args,
        password: password,
        permissions: { set: ['USER'] }
      }
    }, info);
    //create the JWT token for them
    const token = jwt.sign({userId: user.id}, process.env.APP_SECRET)
    //we set the jwt as a cookie on the response
    ctx.response.cookie('token', token, {
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 * 365, //1 Year Cookie = 100ms * 60/min * 60/h * 24/day * 365/year
    });

    //finally we return the user to the browser
    return user; 
  },
  //destructure args in to email and password respectively
  async signin(parents, {email, password}, ctx, info) {
    //check if there is a user with email
    const user = await ctx.db.query.user({where: {email: email}})
    if (!user) {
      throw new Error(`No user found with this ${email}`)
    }
      //check if password is correct
      const valid = await bcrypt.compare(password, user.password);
      if (!valid) {
        throw new Error('Invalid Password')
      }
      //generatr the JWT toeken
      const token = jwt.sign({userId: user.id}, process.env.APP_SECRET)
      //set the cookie with the toekn
      ctx.response.cookie('token', token, {
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 * 365, //1 Year Cookie = 100ms * 60/min * 60/h * 24/day * 365/year
        });
      //return the user
      return user;
  },
  async signout(parents, args, ctx, info) {
    ctx.response.clearCookie('token')
    return {message: 'Goodbye!'}
  },
  async requestReset(parents, args, ctx, info) {
    //1. Check if this is a real user
    const user = await ctx.db.query.user({where: {email: args.email}})
    if (!user) {
      throw new Error(`No user found with this ${args.email}`)
    }
    //2. Set a rest token and expiry on that user
    const randomBytesPromisified = promisify(randomBytes)
    const resetToken = (await randomBytesPromisified(20)).toString('hex')
    const resetTokenExpiry = Date.now() + 36000000; //1 hour from now
    const res = await ctx.db.mutation.updateUser({
      where: {email: args.email},
      data: {resetToken: resetToken, resetTokenExpiry: resetTokenExpiry}
    })
    //3. email them the reset token
    const mailRes = await transport.sendMail({
      from: 'shiva@adiyogi.com',
      to: user.email,
      subject: 'Your Password Reset Token',
      html: makeANiceEmail(`
      <b>${user.name}</b>, 
      \n\n
      Follow this link to reset your password for Shiva Store:
       \n\n
       <a href="${process.env.FRONTEND_URL}/reset?resetToken=${resetToken}">Click to Reset</a>`)
    })
    
    
    //4 Retunr the message
    return {message: 'Thanks, password has been reset!'}
  },
  async resetPassword(parents, args, ctx, info) {
    //1. check if passwords match
    if(args.password !== args.confirmPassword) {
      throw new Error('Yo passwords dont match');
    }
    //2 check if its a legit reset token
    //3 check if it is expired
    const [user] = await ctx.db.query.users({
      where: {
        resetToken: args.resetToken,
        resetTokenExpiry_gte: Date.now() - 36000000
      }
    })
    if(!user) { 
      throw new Error('this token is invalid or expired')
    }
    //4 hash new password
    const password = await bcrypt.hash(args.password, 10);
    
    //5 save new password to user and remove old reset token fields
    const updatedUser = await ctx.db.mutation.updateUser({
      where: {email: user.email},
      data: {password: password, resetToken: null, resetTokenExpiry: null}
    })
    //6 Generate JWT
    const token = jwt.sign({userId: updatedUser.id}, process.env.APP_SECRET)
    //7 Set the JWT Cookie
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365, //1 Year Cookie = 100ms * 60/min * 60/h * 24/day * 365/year
      });
    //8 Return new user
    return updatedUser
  },
  async updatePermissions(parent, args, ctx, info) {
    //Check if logged in
    if(!ctx.request.userId) {
      throw new Error('You are not logged in')
    }
    //Get the current user by the ID
    const currentUser = await ctx.db.query.user({where: {id: ctx.request.userId}}, info)
    //Check if they have permissions 
    hasPermission(currentUser, ['ADMIN', 'PERMISSIONUPDATE'])
    // Update the permissions
    return ctx.db.mutation.updateUser({
      data: {
        permissions: {set: args.permissions}
      },
      where: {id: args.userId},
    },info)
  },
};

module.exports = Mutations;
