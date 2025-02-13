const mongoose = require('mongoose');
const express = require('express');
const authRoute = require('./routes/authRoute');
const config = require('./config/config');

const app = express();

app.use(express.json()); // Middleware for parsing JSON


// Use routes
app.use('/user', authRoute);

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err); // Log the error
    res.status(500).json({ message: err.message }); // Send error response
});

// Connect to MongoDB
mongoose.connect(config.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error(err));

// Start the server
const PORT = process.env.PORT || 7005;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
