import pg from 'pg';
import dotenv from 'dotenv';
import fs from 'fs';
import multer from 'multer';
import * as Minio from 'minio'

dotenv.config();
const upload = multer({ dest: 'uploads/' });


const { Client } = pg;
const db = new Client({
    user: 'postgres',
    host: process.env.DO_HOST,
    database: process.env.DO_DB,
    password: process.env.DO_PG_PW,
    port: process.env.DO_DOCKER_PORT,
});

//hi
const minioClient = new Minio.Client({
    endPoint: process.env.DO_SPACES_ENDPOINT,
    useSSL: true,
    accessKey: process.env.DO_SPACES_ACCESS_ID,
    secretKey: process.env.DO_SPACES_SECRET_ACCESS_KEY,
  });



db.connect();
class movieModel{
    static async getCount(){
        const result = (await db.query("SELECT COUNT (*)FROM Movie")).rows[0];
        return result.count;
    }
    static async getTopRated(){
        const result = (await db.query("SELECT * FROM Movie ORDER BY imdbrating DESC")).rows;
        return result;
    }
    static async getById(imdbID){
        const result = await db.query("SELECT * FROM Movie WHERE imdbID = $1;",[imdbID]);
        return result.rows[0];
    }
    static async getAll(){
        const result = await db.query("SELECT * FROM Movie;");
        return result.rows;
    }
    static async getByTitle(name){
        const result = await db.query("SELECT * FROM Movie WHERE title ILIKE $1",[`%${name}%`]);
        return result.rows;
    }
    static async getByGenre(genre){
        const result = await db.query("SELECT * FROM Movie WHERE genre ILIKE $1",[`%${genre}%`]);
        return result.rows
    }
    static async uploadMovie(file , movie){
        console.log(movie.imdbID);
        const fileStream = fs.createReadStream(file.path);
        const fileStat = fs.statSync(file.path);
    
    try {
        const minioResponse = await new Promise((resolve, reject) => {
            minioClient.putObject('movies', movie.imdbID + '.mp4', fileStream, fileStat.size, (err, objInfo) => {
                if (err) {
                    return reject(err);
                }
                resolve(objInfo);
            });
        });
        console.log('Success', minioResponse);

        // Uncomment and adjust this section if you need to insert the movie data into your database
        const query = `
            INSERT INTO movie ("title", "year", "rated", "released", "runtime", "genre", "actors", "plot", "country", "poster", "imdbrating", "imdbid", "cdnpath", "backdrop")
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        `;
        const values = [
            movie.Title,
            movie.Year,
            movie.rated,
            movie.Released,
            movie.Runtime,
            movie.Genre,
            movie.Actors,
            movie.Plot,
            movie.Country,
            movie.Poster,
            movie.imdbRating,
            movie.imdbID,
            `https://console.tharupathir.live/browser/movies/${movie.imdbID}`,
            movie.Backdrop
        ];
        const result = await db.query(query, values);
        console.log(result)

        return { message: 'File uploaded successfully', data: minioResponse };
    } catch (err) {
        console.error('Error uploading file to MinIO:', err);
        throw err;
    }
    }
    static async getPresignedUrl(movieId) {
        try {
            const url = await new Promise((resolve, reject) => {
                minioClient.presignedUrl('GET', 'movies', movieId + '.mp4', 24 * 60 * 60, (err, presignedUrl) => { // URL valid for 24 hours
                    if (err) {
                        return reject(err);
                    }
                    resolve(presignedUrl);
                });
            });
            return url;
        } catch (err) {
            console.error('Error generating presigned URL:', err);
            throw err;
        }
    }
    static async deleteById(imdbID){
        console.log(imdbID)
        const result =  await db.query("DELETE FROM Movie WHERE imdbid = $1",[imdbID])
        return result;
    }
}

export default movieModel