const { forwardTo } = require('prisma-binding');
const { hasPermission } = require('../utils')

const Query = {
  items: forwardTo('db'),
  item: forwardTo('db'),
  itemsConnection: forwardTo('db'),
  me(parent, args, ctx, info) {
  //check if the is a current user id
    if(!ctx.request.userId) {
      return null;
    }
    return ctx.db.query.user({
      where: {id: ctx.request.userId}
    }, info)
  },
  async users(parent, args, ctx, info) {
    //1 Check if they are logged in
    if (!ctx.request.userId) {
      throw new Error('Not signed in, you must be logged in')
    }
    //2 Check if the user has the permissions to query all the users
    hasPermission(ctx.request.user, ['ADMIN', 'PERMISSIONUPDATE'])
    
    //3 if they do, query all the users
   return ctx.db.query.users({}, info)
  },
  async order(parent, args, ctx, info) {
    //make sure they are logged in
    if (!ctx.request.userId) {
      throw new Error('Not signed in, you must be logged in')
    }
    //query the current order
    const order = await ctx.db.query.order({
      where: {id: args.id}
    }, info)
    //check if they have permissions to se the order
    const ownsOrder = order.user.id === ctx.request.userId
    const hasPermission = ctx.request.user.permissions.includes('USER', 'ADMIN')
    if(!ownsOrder || !hasPermission) {
      throw new Error('You are not allowed to see this')
    }
    //return the order
    return order
  },
  async orders(parent, args, ctx, info) {
    const { userId } = ctx.request;
    if (!userId) {
      throw new Error('you must be signed in!');
    }
    return ctx.db.query.orders(
      {
        where: {
          user: { id: userId },
        },
      },
      info
    );
  },

  /* async items(parent, args, ctx, info) {
    const items = await ctx.db.query.items();
    return items;
  } */
};

module.exports = Query;
