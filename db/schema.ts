import { integer, sqliteTable, text } from 'drizzle-orm/sqlite-core';
export const company = sqliteTable('company',{id:integer('id').primaryKey(), revision:integer('revision').notNull().default(0), data:text('data').notNull()});
