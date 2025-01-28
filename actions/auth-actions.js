'use server';

import { hashUserPassword } from '@/lib/hash';
import { createUser } from '@/lib/user';
import { redirect } from 'next/navigation';

export async function signup(formData) {
  const email = formData.get('email');
  const password = formData.get('password');

  // validate data
  let errors = {};

  if (!email.includes('@')) {
    errors.email = 'Please enter a valid email address';
  }

  if (password.trim().length < 8) {
    errors.password = 'Password must be at least 8 characters long';
  }

  if (Object.keys(errors).length > 0) {
    return {
      errors,
    };
  }

  const hashedPassword = hashUserPassword(password);

  try {
    // store in db (create a user)
    createUser(email, hashedPassword);
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return {
        errors: {
          email: 'Email is already in use',
        },
      };
    }
    throw error;
  }

  redirect('/training');
}
