require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const nodemailer = require('nodemailer');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Multer memory storage
const upload = multer({ storage: multer.memoryStorage() });

// Connect MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Nodemailer transporter
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  }
});

// Schema: Surveyor
const surveyorSchema = new mongoose.Schema({
  fullname: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  surveyorId: { type: String, unique: true, required: true },
  passwordHash: { type: String, required: true },
  profilePhotoUrl: String,
});

const Surveyor = mongoose.model('Surveyor', surveyorSchema);

// Schema: Photo
const photoSchema = new mongoose.Schema({
  surveyorId: String,
  fullname: String,
  email: String,
  imageId: { type: String, unique: true },
  photoUrl: String,
  location: {
    street: String,
    city: String,
    region: String,
    country: String,
    latitude: Number,
    longitude: Number,
  },
  roadName: String,
  damageClass: String,
  comment: String,
  localTime: String,
  dateCreated: { type: Date, default: Date.now }
});

const Photo = mongoose.model('Photo', photoSchema);

// Helper: Email sender
function sendEmail(to, subject, text) {
  return transporter.sendMail({ from: process.env.EMAIL_USER, to, subject, text });
}

// ===== REGISTER route =====
app.post('/register', async (req, res) => {
  try {
    const { fullname, email, surveyorId, password, confirmPassword } = req.body;

    // Validate input
    if (!fullname || !email || !surveyorId || !password || !confirmPassword) {
      return res.status(400).json({ message: 'All fields are required.' });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ message: 'Passwords do not match.' });
    }

    // Check if surveyor ID already exists
    const existingID = await Surveyor.findOne({ surveyorId: surveyorId.trim() });
    if (existingID) {
      return res.status(400).json({ message: 'Surveyor ID already exists. Please use a different ID.' });
    }

    // Check if email already used
    const existingEmail = await Surveyor.findOne({ email: email.trim().toLowerCase() });
    if (existingEmail) {
      return res.status(400).json({ message: 'Email already registered.' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new surveyor
    const newSurveyor = new Surveyor({
      fullname: fullname.trim(),
      email: email.trim().toLowerCase(),
      surveyorId: surveyorId.trim(),
      passwordHash: hashedPassword,
    });

    await newSurveyor.save();
    return res.status(201).json({ message: 'Registration successful. You can now login.' });

  } catch (err) {
    console.error('Register Error:', err);
    return res.status(500).json({ message: 'Internal server error. Please try again later.' });
  }
});

// ===== LOGIN route =====
app.post('/login', async (req, res) => {
  try {
    const { surveyorId, password } = req.body;
    if (!surveyorId || !password)
      return res.status(400).json({ message: 'Surveyor ID and password required' });

    const user = await Surveyor.findOne({ surveyorId });
    if (!user) return res.status(400).json({ message: 'Invalid Surveyor ID or password' });

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) return res.status(400).json({ message: 'Invalid Surveyor ID or password' });

    const token = jwt.sign({ surveyorId: user.surveyorId }, process.env.JWT_SECRET, { expiresIn: '12h' });

    res.json({
      token,
      fullname: user.fullname,
      email: user.email,
      surveyorId: user.surveyorId,
      profilePhotoUrl: user.profilePhotoUrl || '',
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ===== Upload captured photo =====
app.post('/upload-photo', async (req, res) => {
  try {
    const {
      surveyorId,
      fullname,
      email,
      imageData,
      location,
      roadName,
      damageClass,
      comment,
      localTime
    } = req.body;

    if (!imageData) return res.status(400).json({ message: 'Missing image data' });

    const uploadRes = await cloudinary.uploader.upload(imageData, {
      folder: 'road_damage',
      public_id: `photo_${Date.now()}`,
    });

    const newPhoto = new Photo({
      surveyorId,
      fullname,
      email,
      imageId: uploadRes.public_id,
      photoUrl: uploadRes.secure_url,
      location,
      roadName,
      damageClass,
      comment,
      localTime
    });

    await newPhoto.save();
    res.json({ message: 'Photo uploaded successfully', url: uploadRes.secure_url });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ message: 'Server error during photo upload' });
  }
});

// ===== Delete account =====
app.delete('/delete-account', async (req, res) => {
  try {
    const { surveyorId } = req.body;
    if (!surveyorId) return res.status(400).json({ message: 'Surveyor ID is required' });

    await Surveyor.deleteOne({ surveyorId });
    await Photo.deleteMany({ surveyorId });

    res.json({ message: 'Account and photos deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error deleting account' });
  }
});

// ===== Upload profile photo =====
app.post('/upload-profile-photo', upload.single('profilePhoto'), async (req, res) => {
  try {
    const { surveyorId } = req.body;
    const file = req.file;
    if (!file || !surveyorId) return res.status(400).json({ message: 'Missing file or ID' });

    // Use a promise wrapper for upload_stream
    const uploadFromBuffer = (buffer) => new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream({ folder: 'profile_photos' }, (error, result) => {
        if (error) reject(error);
        else resolve(result);
      });
      stream.end(buffer);
    });

    const result = await uploadFromBuffer(file.buffer);

    await Surveyor.updateOne({ surveyorId }, { profilePhotoUrl: result.secure_url });
    res.json({ message: 'Profile photo uploaded', url: result.secure_url });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error uploading profile photo' });
  }
});

// ===== Get profile photo URL =====
app.get('/get-profile-photo', async (req, res) => {
  try {
    const { surveyorId } = req.query;
    const user = await Surveyor.findOne({ surveyorId });
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ url: user.profilePhotoUrl || '' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error retrieving profile photo' });
  }
});

// ===== Admin: Delete one photo =====
app.delete('/delete-photo/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const photo = await Photo.findById(id);
    if (!photo) return res.status(404).json({ message: 'Photo not found' });

    // Delete from Cloudinary
    if (photo.imageId) {
      await cloudinary.uploader.destroy(photo.imageId);
    }

    await Photo.findByIdAndDelete(id);
    res.json({ message: 'Photo deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Failed to delete photo' });
  }
});

// ===== Admin: Get all photos with optional filtering =====
app.get('/get-all-photos', async (req, res) => {
  try {
    const { damageClass, startDate, endDate } = req.query;
    const filter = {};

    if (damageClass) filter.damageClass = damageClass;
    if (startDate || endDate) {
      filter.dateCreated = {};
      if (startDate) filter.dateCreated.$gte = new Date(startDate);
      if (endDate) filter.dateCreated.$lte = new Date(endDate);
    }

    const photos = await Photo.find(filter).sort({ dateCreated: -1 });
    res.json({ photos });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Failed to fetch photos' });
  }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
