const Mutations = {
  async createItem(parent, args, ctx, info) {
    // TODO Check if they are logged in
    console.log(ctx.db);
    const item = await ctx.db.mutation.createItem(
      {
        data: {
          ...args
        }
      },
      info
    );

    return item;
  }
  /*   createDog: function(parent, args, ctx, info) {
    global.dogs = global.dogs || [];
    const newDog = { name: args.name };
    global.dogs.push(newDog);
    console.log(args);
  } */
};

module.exports = Mutations;
