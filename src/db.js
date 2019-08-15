//This file connect  to the remot eprimsa db and gives us the ability to quert it with JS
const { Prisma } = require('prisma-binding');

const db = new Prisma({
  typeDefs: 'src/generated/prisma.graphql',
  endpoint: process.env.PRISMA_ENDPOINT,
  /*  secret: process.env.PRISMA_SECRET, */
  debug: false
});

module.exports = db;
