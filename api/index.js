import app from '../server/index.js';

// Vercel Serverless Function configuration
// Disables Vercel's default body parser so Multer can process multipart/form-data streams
export const config = {
  api: {
    bodyParser: false
  }
};

export default app;
