const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const path = require('path');
const session = require("express-session");
const methodOverride = require("method-override");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
const { param, query, validationResult } = require('express-validator');
const rateLimit = require("express-rate-limit");
const axios = require('axios');
const crypto = require('crypto');
const multer = require('multer');
const User = require('./models/user.model');


require("dotenv").config();

// Function to generate a random token
function generateRandomToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Initialize Passport
const initializePassport = require("./config/passport-config");
initializePassport(
    passport,
    async (email) => {
        try {
            return await User.findOne({ email: email });
        } catch (error) {
            console.error('Error finding user by email:', error);
            throw error;
        }
    },
    async (id) => {
        try {
            return await User.findById(id);
        } catch (error) {
            console.error('Error finding user by ID:', error);
            throw error;
        }
    }
);

mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    dbName: 'OptionChain',
})
    .then(() => {
        console.log('Connected to MongoDB');
    })
    .catch(error => {
        console.error('Error connecting to MongoDB:', error);
        process.exit(1);
});

app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(
    session({
        secret: process.env.SESSION_SECRET || generateRandomSecret(),
        resave: false,
        saveUninitialized: false,
    })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));

// Options chain data storage
const tickerData = {};
const cache1 = {};

const validateParameters = [
    param('ticker').isString(),
    query('exp').isString().optional(),
    query('time').isNumeric().optional(),
];

const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 300,
});
app.use(limiter);

// Historical options chain endpoint
app.get('/api/hoc/symbol=:ticker', validateParameters, async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
  
      const { ticker } = req.params;
      const expiry = req.query.exp;
      const timestamp = req.query.time;
  
      // Check if the data is present in the cache
      const cache1Key = `${ticker}_${expiry || ''}_${timestamp || ''}`;
      if (cache1[cache1Key] && cache1[cache1Key].timestamp + 30000 > Date.now()) {
        // Data is present in the cache and is not expired
        res.json(cache1[cache1Key].data);
        return;
      }
  
      const apiUrl = `https://api.niftychain.in/api/historical-data?ticker=${ticker}&expiry=${expiry}&timestamp=${timestamp}`;
  
      const response = await axios.get(apiUrl);
      const responseData = response.data.data; // Access the [data] property
  
      const extractedData = {
        optionsData: responseData.data.map(option => ({
          strike: option.strikePrice, 
          call: {
            ...option.ce,
            sor: option.ce.eos,
            ltp: option.ce.lastPrice,
            chngltp: option.ce.change,
            actualSor: option.ce.averageEos,
            FutureSor: option.ce.eosF,
          },
          put: {
            ...option.pe,
            sos: option.pe.eos,
            ltp: option.pe.lastPrice,
            chngltp: option.pe.change,
            actualSos: option.pe.averageEos,
            FutureSos: option.ce.eosF,
          },
        })),
        underlyingValue: responseData.underlyingValue,
        symbol: responseData.ticker,
        dataTime: responseData.timestamp
      };
  
      extractedData.optionsData.forEach(option => {
        option.call.sor = option.call.eos;
        option.call.ltp = option.call.lastPrice;
        option.call.chngltp = option.call.change;
        option.call.actualSor = option.call.averageEos;
        option.call.FutureSor = option.call.eosF;
        delete option.call.eosF;
        delete option.call.averageEos;
        delete option.call.change;
        delete option.call.eos;
        delete option.call.lastPrice;
      });
  
      extractedData.optionsData.forEach(option => {
        option.put.sos = option.put.eos;
        option.put.ltp = option.put.lastPrice;
        option.put.chngltp = option.put.change;
        option.put.actualSos = option.put.averageEos;
        option.put.FutureSos = option.put.eosF;
        delete option.put.eosF;
        delete option.put.averageEos;
        delete option.put.change;
        delete option.put.eos;
        delete option.put.lastPrice;
      });
  
      tickerData[ticker] = extractedData;
  
      // Cache the result for 30 seconds
      cache1[cache1Key] = { data: extractedData, timestamp: Date.now() };
  
      res.json(extractedData);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });
  
  // Ticker data logging
  setInterval(() => {
    console.log('Ticker Data:');
    Object.keys(tickerData).forEach(ticker => {
      console.log(`  ${ticker}:`, tickerData[ticker]);
    });
  }, 30000); // 30sec wait for next req)

// Assuming you have a global variable for caching
let cache = {};

app.get('/api/optionchain/:symbol', async (req, res) => {
  const symbol = req.params.symbol;
  const dateTime = req.query.dateTime;

  try {
    // Check if the data is present in the cache
    const cacheKey = `${symbol}_${dateTime || 'all'}`;
    if (cache[cacheKey] && cache[cacheKey].timestamp + 30000 > Date.now()) {
      // Data is present in the cache and is not expired
      res.json(cache[cacheKey].data);
      return;
    }
    const db = mongoose.connection.db;
    const collection = db.collection('Oc_Data');

    const filter = { symbol: symbol };
    const allItemsBySymbol = await collection.find(filter).toArray();

    if (allItemsBySymbol.length === 0) {
      res.status(404).sendFile(path.join(__dirname, '..', 'public', '404.html'));
      return;
    }

    if (dateTime) {
      const targetDateTime = Number(dateTime);
      const closestItem = allItemsBySymbol.reduce((closest, current) => {
        const currentDateTime = current.dataTime;
        const closestDateTime = closest.dataTime || 0;
        const currentDiff = Math.abs(currentDateTime - targetDateTime);
        const closestDiff = Math.abs(closestDateTime - targetDateTime);
        return currentDiff < closestDiff ? current : closest;
      });

      // Cache the result for 30 seconds
      cache[cacheKey] = { data: { optionChains: [closestItem] }, timestamp: Date.now() };
      res.json({ optionChains: [closestItem] });
    } else {
      // Cache the result for 30 seconds
      cache[cacheKey] = { data: { optionChains: allItemsBySymbol }, timestamp: Date.now() };
      res.json({ optionChains: allItemsBySymbol });
    }
  } catch (error) {
    console.error('Database Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get("/index", checkAuthenticated, (req, res) => {
    res.render("index.ejs", { user: req.user, success: req.flash('success') });
});

app.get("/", checkAuthenticated, (req, res) => {
    res.render("dashboard.ejs", { user: req.user, success: req.flash('success') });
});

app.get("/login", checkNotAuthenticated, (req, res) => {
    res.render("login.ejs");
});

app.post(
    "/login",
    checkNotAuthenticated,
    passport.authenticate("local", {
        successRedirect: "/",
        failureRedirect: "/login",
        failureFlash: true,
        successFlash: 'Login successful! Welcome back.',
    })
);

app.get("/register", checkNotAuthenticated, (req, res) => {
    res.render("register.ejs");
});

app.post("/register", checkNotAuthenticated, async (req, res) => {
    try {
        const existingUser = await User.findOne({ email: req.body.email });

        if (existingUser) {
            req.flash("error", "Email is already registered. Please use a different email.");
            return res.redirect("/register");
        }

        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = new User({
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword,
        });

        await user.save();

        // Send verification email
        const verificationToken = generateVerificationToken();
        user.emailVerificationToken = verificationToken;
        await user.save();

        const verificationLink = `${process.env.BASE_URL}/verify-email/${verificationToken}`;
        const mailOptions = {
            from: process.env.GMAIL_USER,
            to: user.email,
            subject: "Email Verification",
            text: `Click the following link to verify your email: ${verificationLink}`,
        };

        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: process.env.GMAIL_USER,
                pass: process.env.GMAIL_PASS,
            },
        });

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error(error);
                req.flash('error', 'Failed to send verification email');
            } else {
                console.log("Email sent: " + info.response);
                req.flash('success', 'Verification email sent successfully');
            }
            res.redirect("/login");
        });
    } catch (error) {
        console.error(error);
        res.redirect("/register");
    }
});

app.get("/forgot-password", checkNotAuthenticated, (req, res) => {
    res.render("forgotPassword.ejs");
});

app.post("/forgot-password", checkNotAuthenticated, async (req, res) => {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
        req.flash("error", "No user found with that email");
        return res.redirect("/forgot-password");
    }

    const resetToken = generateRandomToken();
    const resetTokenExpiration = new Date();
    resetTokenExpiration.setHours(resetTokenExpiration.getHours() + 1);

    user.resetToken = resetToken;
    user.resetTokenExpiration = resetTokenExpiration;
    await user.save();

    const resetLink = `https://Futureview.vercel.app/reset-password/${resetToken}`;
    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.GMAIL_USER,
            pass: process.env.GMAIL_PASS,
        },
    });

    const mailOptions = {
        from: process.env.GMAIL_USER,
        to: user.email,
        subject: "Password Reset",
        text: `Click the following link to reset your password: ${resetLink}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error(error);
            req.flash("error", "Failed to send reset email");
            return res.redirect("/forgot-password");
        } else {
            console.log("Email sent: " + info.response);
            req.flash("success", "Password reset email sent successfully");
            res.redirect("/login");
        }
    });
});

app.get("/reset-password/:token", checkNotAuthenticated, async (req, res) => {
    const token = req.params.token;
    const user = await User.findOne({
        resetToken: token,
        resetTokenExpiration: { $gt: new Date() },
    });

    if (!user) {
        req.flash("error", "Invalid or expired reset token");
        return res.redirect("/forgot-password");
    }

    res.render("resetPassword.ejs", { token, success: req.flash('success') });
});

app.post("/reset-password/:token", checkNotAuthenticated, async (req, res) => {
    const token = req.params.token;
    const user = await User.findOne({
        resetToken: token,
        resetTokenExpiration: { $gt: new Date() },
    });

    if (!user) {
        req.flash("error", "Invalid or expired reset token");
        return res.redirect("/forgot-password");
    }

    const newPassword = req.body.password;
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiration = undefined;

    await user.save();

    req.flash('success', 'Password reset successfully. You can now log in.');
    res.redirect("/login");
});

app.get("/profile", checkAuthenticated, (req, res) => {
    res.render("profile.ejs", {
        user: req.user,
        isEmailVerified: req.user.emailVerified,
        success: req.flash('success'),
        error: req.flash('error')
    });
});

app.post("/profile/update", checkAuthenticated, async (req, res) => {
    const { name, email } = req.body;

    try {
        const user = req.user;

        if (name) user.name = name;
        if (email) {
            // Check if the new email is different from the current one
            if (user.email !== email) {
                user.email = email;
                user.emailVerified = false; // Set emailVerified to false when email changes

                // Send verification email for the new email
                const verificationToken = generateVerificationToken();
                user.emailVerificationToken = verificationToken;
                
                const verificationLink = `${process.env.BASE_URL}/verify-email/${verificationToken}`;
                const mailOptions = {
                    from: process.env.GMAIL_USER,
                    to: user.email,
                    subject: 'Email Verification',
                    text: `Click the following link to verify your email: ${verificationLink}`,
                };

                const transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        user: process.env.GMAIL_USER,
                        pass: process.env.GMAIL_PASS,
                    },
                });

                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.error(error);
                        req.flash('error', 'Failed to send verification email');
                    } else {
                        console.log("Email sent: " + info.response);
                        req.flash('success', 'Verification email sent successfully');
                    }
                    
                    // Redirect to the profile page after sending the verification email
                    res.redirect('/profile');
                });
            }
        }

        await user.save();

        req.flash('success', 'Profile updated successfully.');
        res.redirect("/profile");
    } catch (error) {
        console.error(error);
        req.flash('error', 'Error updating profile.');
        res.redirect("/profile");
    }
});

// Change Password in User Profile
app.post('/profile/change-password', checkAuthenticated, async (req, res) => {
    const { oldPassword, newPassword, confirmNewPassword } = req.body;

    try {
        const user = req.user;

        // Check if the old password is correct
        const isMatch = await bcrypt.compare(oldPassword, user.password);

        if (!isMatch) {
            req.flash('error', 'Old password is incorrect.');
            return res.redirect('/profile');
        }

        // Check if the new password and confirmation match
        if (newPassword !== confirmNewPassword) {
            req.flash('error', 'New password and confirmation do not match.');
            return res.redirect('/profile');
        }

        // Update the password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;

        await user.save();

        req.flash('success', 'Password changed successfully.');
        res.redirect('/profile');
    } catch (error) {
        console.error(error);
        req.flash('error', 'Error changing password.');
        res.redirect('/profile');
    }
});

app.get('/profile/send-verification', checkAuthenticated, async (req, res) => {
    try {
        const user = req.user;

        // Check if the email is already verified
        if (user.emailVerified) {
            req.flash('success', 'Email is already verified.');
            return res.redirect('/profile');
        }

        const verificationToken = generateVerificationToken();
        user.emailVerificationToken = verificationToken;
        await user.save();

        const verificationLink = `${process.env.BASE_URL}/verify-email/${verificationToken}`;
        const mailOptions = {
            from: process.env.GMAIL_USER,
            to: user.email,
            subject: 'Email Verification',
            text: `Click the following link to verify your email: ${verificationLink}`,
        };

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.GMAIL_USER,
                pass: process.env.GMAIL_PASS,
            },
        });

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error(error);
                req.flash('error', 'Failed to send verification email');
            } else {
                console.log("Email sent: " + info.response);
                req.flash('success', 'Verification email sent successfully');
            }
            
            // Redirect to the profile page after sending the verification email
            res.redirect('/profile');
        });
    } catch (error) {
        console.error(error);
        req.flash('error', 'Error sending verification email');
        res.redirect('/profile');
    }
});

app.get("/verify-email/:token", async (req, res) => {
    const token = req.params.token;
    const user = await User.findOne({
        emailVerificationToken: token,
    });

    if (!user) {
        req.flash("error", "Invalid verification token");
    } else {
        user.emailVerified = true;
        user.emailVerificationToken = undefined;
        await user.save();
        req.flash("success", "Email verification successful");
    }

    res.redirect("/profile");
});

// Update Profile Picture Endpoint
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

app.post('/profile/update-profile-pic', checkAuthenticated, upload.single('profilePic'), async (req, res) => {
    try {
        const user = req.user;

        // Check if a file was uploaded
        if (req.file) {
            // Save the uploaded image data to the user's profilePic property
            user.profilePic = {
                data: req.file.buffer,
                contentType: req.file.mimetype, // Use the MIME type provided by multer
            };

            // Save the updated user data to the database
            await user.save();

            // Redirect back to the profile page
            return res.redirect('/profile');
        }

        // If no file was uploaded
        req.flash('error', 'No file was uploaded.');
        return res.redirect('/profile');
    } catch (error) {
        console.error('Error updating profile picture:', error);
        req.flash('error', 'Error updating profile picture. Please try again.');
        return res.redirect('/profile');
    }
});

// Display Profile Picture
app.get('/profile/profile-pic/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id);

        if (!user || !user.profilePic) {
            return res.status(404).send('Profile picture not found');
        }

        res.set('Content-Type', user.profilePic.contentType);
        res.send(user.profilePic.data);
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

// remove profile pic
app.post('/profile/remove-profile-pic', checkAuthenticated, async (req, res) => {
    try {
        const user = req.user;

        // Check if the user has a profile picture
        if (user.profilePic && user.profilePic.data) {
            // Remove the profile picture data from the user
            user.profilePic = undefined;

            // Save the updated user data to the database
            await user.save();

            req.flash('success', 'Profile picture removed successfully.');
        } else {
            req.flash('error', 'No profile picture found.');
        }

        // Redirect back to the profile page
        res.redirect('/profile');
    } catch (error) {
        console.error(error);
        req.flash('error', 'Error removing profile picture.');
        res.redirect('/profile');
    }
});

app.post('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            return res.status(500).json({ message: 'Logout failed', error: err });
        }
        res.redirect('/');
    });
});

app.get("/privacy-policy", (req, res) => {
    res.render("privacy-policy.ejs");
});

app.get("/terms-of-service", (req, res) => {
    res.render("terms-of-service.ejs");
});

app.use((req, res) => {
    res.status(404).render('404.ejs');
});

function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect("/login");
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect("/");
    }
    next();
}

function isLoggedIn(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect("/login");
}

function generateVerificationToken() {
    return crypto.randomBytes(32).toString('hex');
}

function generateRandomSecret() {
    return crypto.randomBytes(64).toString('hex');
}

// Set up views and EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
console.log(`Server is running on port ${PORT}`);
});
