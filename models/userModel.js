import dotenv from 'dotenv';
import pg from 'pg';
import bcrypt from 'bcrypt';
import fetch from 'node-fetch';

dotenv.config();

const { Client } = pg;
const saltRounds = 10;

// Database connection
const db = new Client({
    user: process.env.DO_USER || 'postgres',
    host: process.env.DO_HOST,
    database: process.env.DO_DB,
    password: process.env.DO_PG_PW,
    port: process.env.DO_DOCKER_PORT || 5432,
});

db.connect().catch(err => {
    console.error('Error connecting to the database:', err.stack);
});

class UserModel {
    // Fetch all users
    static async getAll() {
        try {
            const result = await db.query('SELECT * FROM users');
            return result.rows;
        } catch (error) {
            console.error('Error fetching users:', error);
            throw error;
        }
    }

    // Check if user exists by email
    static async checkExist(email) {
        try {
            const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
            return result.rows.length > 0;
        } catch (error) {
            console.error('Error checking if user exists:', error);
            throw error;
        }
    }

    // Fetch hashed password by email
    static async getUserHash(email) {
        try {
            const result = await db.query('SELECT hash FROM users WHERE email = $1', [email]);
            return result.rows[0]?.hash || null;
        } catch (error) {
            console.error('Error fetching user hash:', error);
            throw error;
        }
    }

    // Add a new user
    static async addUser(userName, password, email, role) {
        try {
            const hash = bcrypt.hashSync(password, saltRounds);
            const checkExist = await this.checkExist(email);

            if (!checkExist) {
                const result = await db.query(
                    'INSERT INTO users (username, hash, email, role) VALUES ($1, $2, $3, $4) RETURNING *',
                    [userName, hash, email, role]
                );
                return result.rows[0];
            } else {
                console.log('User already exists');
                return null;
            }
        } catch (error) {
            console.error('Error adding user:', error);
            throw error;
        }
    }

    // User login
    static async logIn(email, password) {
        try {
            const userExists = await this.checkExist(email);
            if (userExists) {
                const hash = await this.getUserHash(email);
                if (!hash) {
                    console.log('No hash found for user');
                    return false;
                }

                const match = await bcrypt.compare(password, hash);
                if (match) {
                    console.log('Password matched');
                    return true;
                } else {
                    console.log('Password incorrect');
                    return false;
                }
            } else {
                console.log('User does not exist');
                return false;
            }
        } catch (error) {
            console.error('Error logging in:', error);
            throw error;
        }
    }

    // Check if the user is logged in
    static async isLogged(req) {
        try {
            return req.isAuthenticated();
        } catch (error) {
            console.error('Error checking login status:', error);
            throw error;
        }
    }

    // Count all users
    static async count() {
        try {
            const result = await db.query('SELECT COUNT(*) FROM users');
            return parseInt(result.rows[0].count, 10);
        } catch (error) {
            console.error('Error counting users:', error);
            throw error;
        }
    }

    // Fetch user data using OAuth2 access token
    static async getUserData(access_token) {
        try {
            const response = await fetch(`https://www.googleapis.com/oauth2/v3/userinfo?access_token=${access_token}`);
            const data = await response.json();
            console.log('OAuth2 User Data:', data);
            return data;
        } catch (error) {
            console.error('Error fetching OAuth2 user data:', error);
            throw error;
        }
    }
}

export default UserModel;