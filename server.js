const express = require('express');
const cors = require('cors');
const axios = require('axios');
const multer = require('multer');
require('dotenv').config();

const app = express();

const corsOptions = {
    origin: process.env.ui_url,
    methods: ['POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: false
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
            // Instead of throwing an error, reject with false and a message
            return cb(null, false);
        }
        cb(null, true);
    }
}).single('files');

// Custom middleware to handle multer upload
const handleUpload = (req, res, next) => {
    upload(req, res, function(err) {
        if (err) {
            // Handle multer-specific errors
            return res.status(400).json({
                success: false,
                message: 'File upload failed',
                error: err.message
            });
        }
        
        // Handle file type rejection
        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: 'Please upload a valid PDF file'
            });
        }
        
        next();
    });
};

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
        return {
            success: false,
            message: 'Invalid PDF format'
        };
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
        return {
            success: false,
            message: 'PDF security check failed: Potentially unsafe content detected'
        };
    }

    return { success: true };
}

// Secure Upload endpoint
app.post('/api/upload', handleUpload, async (req, res) => {
    try {
        // Perform security check
        const securityCheck = await checkPDFSecurity(req.file.buffer);
        if (!securityCheck.success) {
            return res.status(400).json({
                success: false,
                message: securityCheck.message
            });
        }

        // Forward to Strapi
        const formData = new FormData();
        const blob = new Blob([req.file.buffer], { type: 'application/pdf' });
        formData.append('files', blob, req.file.originalname);

        const strapiUrl = `${process.env.cms_url}/api/upload`;
        const response = await axios.post(strapiUrl, formData, {
            headers: {
                ...(req.headers.authorization && { 'Authorization': req.headers.authorization })
            }
        });

        res.status(200).json({
            success: true,
            message: 'File uploaded successfully',
            data: response.data
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Server error during file upload',
            error: error.message
        });
    }
});

const PORT = 3005;
app.listen(PORT, () => {
    console.log(`🚀 Secure proxy server running on port ${PORT}`);
});