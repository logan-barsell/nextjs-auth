'use server';

import { createAuthSession, destroySession } from '@/lib/auth';
import { hashUserPassword, verifyPassword } from '@/lib/hash';
import { createUser, getUserByEmail } from '@/lib/user';
import { redirect } from 'next/navigation';

export async function signup(prevState, formData) {
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
    const id = createUser(email, hashedPassword);
    await createAuthSession(id);
    redirect('/training');
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
}

export async function login(prevState, formData) {
  const email = formData.get('email');
  const password = formData.get('password');

  // check if user exists with this email
  const existingUser = getUserByEmail(email);
  if (!existingUser) {
    return {
      errors: {
        user: 'Could not authenticate user, please check your credentials',
      },
    };
  }

  // check if passwords match
  const passMatch = verifyPassword(existingUser.password, password);
  if (!passMatch) {
    return {
      errors: {
        user: 'Could not authenticate user, please check your credentials',
      },
    };
  }

  // create authentication session and redirect
  await createAuthSession(existingUser.id);
  redirect('/training');
}

export async function auth(mode, prevState, formData) {
  console.log(mode, prevState, formData);
  if (mode === 'login') {
    return login(prevState, formData);
  }
  return signup(prevState, formData);
}

export async function logout() {
  console.log('LOGOUT');
  await destroySession();
  redirect('/');
}
