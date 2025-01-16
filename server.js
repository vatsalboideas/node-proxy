const express = require('express');
const cors = require('cors');
const axios = require('axios');
const multer = require('multer');
require('dotenv').config();


const app = express();

const corsOptions = {
    origin: ['http://localhost:3000'], // Allow specific origins
    methods: ['POST'],                  // Allowed HTTP methods
    allowedHeaders: ['Content-Type', 'Authorization'],          // Allowed headers
    credentials: false                                           // Allow cookies and credentials
  };

app.use(cors(corsOptions));
app.use(express.json());

// Configure multer for PDF uploads
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype !== 'application/pdf') {
      cb(new Error('Only PDF files are allowed'), false);
      return;
    }
    cb(null, true);
  },
});

// PDF Security Check Function
async function checkPDFSecurity(buffer) {
  const fileContent = buffer.toString();
  
  const securityChecks = {
    hasJavaScript: false,
    hasEncryption: false,
    hasEmbeddedFiles: false,
    hasAcroForms: false,
    suspiciousPatterns: [],
    headerCheck: false
  };

  // Check PDF header
  const pdfHeader = buffer.slice(0, 5).toString();
  securityChecks.headerCheck = pdfHeader === '%PDF-';

  if (!securityChecks.headerCheck) {
    throw new Error('Invalid PDF format');
  }

  // Check for dangerous patterns
  const patterns = {
    javascript: ['/JS', '/JavaScript', '/AA', '/OpenAction'],
    embedded: ['/EmbeddedFiles', '/EF'],
    forms: ['/AcroForm'],
    other: ['/Launch', '/SubmitForm', '/ImportData', '/RichMedia', '/XFA']
  };

  Object.entries(patterns).forEach(([category, patternList]) => {
    patternList.forEach(pattern => {
      if (fileContent.includes(pattern)) {
        if (category === 'javascript') securityChecks.hasJavaScript = true;
        if (category === 'embedded') securityChecks.hasEmbeddedFiles = true;
        if (category === 'forms') securityChecks.hasAcroForms = true;
        securityChecks.suspiciousPatterns.push(pattern);
      }
    });
  });

  if (fileContent.includes('/Encrypt')) {
    securityChecks.hasEncryption = true;
  }

  const isHighRisk = securityChecks.hasJavaScript || 
                     securityChecks.hasEmbeddedFiles || 
                     securityChecks.suspiciousPatterns.length > 0;
  const isMediumRisk = securityChecks.hasEncryption || 
                       securityChecks.hasAcroForms;

  if (isHighRisk || isMediumRisk) {
    throw new Error(`PDF security check failed: ${
      isHighRisk ? 'High-risk' : 'Medium-risk'
    } content detected`);
  }

  return true;
}

// Secure Upload endpoint
app.post('/api/upload', upload.single('files'), async (req, res) => {
  console.log('⭐ Received upload request');
  
  try {
    if (!req.file) {
      throw new Error('No file uploaded');
    }

    // Perform security check
    await checkPDFSecurity(req.file.buffer);

    // Forward to Strapi
    const formData = new FormData();
    const blob = new Blob([req.file.buffer], { type: 'application/pdf' });
    formData.append('files', blob, req.file.originalname);

    const strapiUrl = `${process.env.cms_url}/api/upload`;
    const response = await axios.post(strapiUrl, formData, {
      headers: {
        // ...formData.getHeaders(),
        ...(req.headers.authorization && { 'Authorization': req.headers.authorization })
      },
    //   maxBodyLength: Infinity,
    //   timeout: 30000
    });

    console.log(response.data,'✅ Upload successful');
    res.status(response.status).json(response.data);

  } catch (error) {
    console.error('❌ Upload error:', error.message);
    res.status(error.response?.status || 500).json({
      error: true,
      message: error.message,
      details: error.response?.data || 'Upload failed'
    });
  }
});

// Forward all other API requests to Strapi
// app.all('/api/*', async (req, res) => {
//   if (req.path === '/api/upload') return; // Skip if it's an upload request

//   try {
//     const strapiUrl = `${process.env.cms_url}${req.path}`;
//     const response = await axios({
//       method: req.method,
//       url: strapiUrl,
//       data: req.body,
//       params: req.query,
//       headers: {
//         ...(req.headers.authorization && { 'Authorization': req.headers.authorization })
//       },
//       timeout: 5000
//     });
    
//     res.status(response.status).json(response.data);
    
//   } catch (error) {
//     res.status(error.response?.status || 500).json({
//       error: true,
//       message: error.message,
//       details: error.response?.data || 'No additional details'
//     });
//   }
// });

const PORT = 3005;
app.listen(PORT, () => {
  console.log(`🚀 Secure proxy server running on port ${PORT}`);
});