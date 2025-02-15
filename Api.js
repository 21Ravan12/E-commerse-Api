// Required modules
const express = require('express');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const Joi = require('joi');

// Initialize the Express app
const app = express();

// Middleware setup
app.use(cors()); // Enable Cross-Origin Resource Sharing
app.use(bodyParser.json({ limit: '10mb' })); // Parse JSON with size limit
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' })); // Parse URL-encoded data

const port = 3002; // Server port

// Database connection setup
const db = mysql.createConnection({
  host: 'localhost', // Database host
  user: 'root', // Database username
  password: '', // Database password
  database: 'e-commerse-db', // Database name
});

// Connect to the database and handle errors
// Ensure the database is running and credentials are correct
// Log a message when connected successfully
// Otherwise, log the error

// Connect to the MySQL database
db.connect((err) => {
  if (err) console.error(err.message); // Log the error if connection fails
  else console.log('Connected to MySQL database.'); // Success message
});


// Email transport configuration
// Hardcoded credentials should be replaced with environment variables
const transporter = nodemailer.createTransport({
  service: 'gmail', // Email service provider
  auth: {
    user: '', // Your email
    pass: '', // Your app password
  }
});

// Function to send verification codes via email
const sendCodeEmail = async (email, code) => {
  const mailOptions = {
    from: '', // Sender's email
    to: email, // Recipient's email
    subject: 'Identification', // Email subject
    text: `Your identification code is: ${code}`, // Email body
  };

  try {
    await transporter.sendMail(mailOptions); // Send the email
    console.log("Email sent successfully!"); // Log success
  } catch (err) {
    console.error("Email error:", err); // Log any errors
    throw new Error(`Failed to send email. ${err.message}`); // Throw error for further handling
  }
};

// Maps for temporary data storage (e.g., verification codes)
// Note: Temporary in-memory storage will be lost on server restart
const signinStorage = new Map(); // Stores sign-in data
const forgetStorage = new Map(); // Reserved for forgot-password functionality

// API route for user registration (Step 1: Send verification code)
app.post('/api/enter', async (req, res) => {
  const { email, password, name, birthyear } = req.body;

  try {
    // Validate request body using Joi schema
    const schema = Joi.object({
      email: Joi.string().email().required(),
      password: Joi.string().min(8).required(),
      name: Joi.string().min(2).required(),
      birthyear: Joi.number().integer().min(1900).max(new Date().getFullYear()).required(),
    });

    const { error } = schema.validate(req.body); // Validate user input
    if (error) {
      return res.status(400).json({ message: error.details[0].message }); // Return validation error
    }

    // Check if email already exists in the database
    const checkQuery = 'SELECT * FROM users WHERE email = ?';
    db.query(checkQuery, [email], async (err, results) => {
      if (err) {
        console.error(err.message); // Log SQL error
        return res.status(500).json({ message: 'Error checking user email.' });
      }

      if (results.length > 0) {
        // If email already exists, return an error response
        return res.status(400).json({ message: 'Email already exists.' });
      }

      // Hash the password for security
      let hashedPassword = await bcrypt.hash(password, 10);
      console.log("Hashed password:", hashedPassword); // Log the hashed password

      // Generate a random 6-digit verification code
      const randomCode = Math.floor(Math.random() * 999999) + 1;

      // Set an expiry time for the code (15 minutes from now)
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

      // Store user data in the temporary map
      signinStorage.set(email, {
        email,
        password: hashedPassword,
        name,
        birthyear,
        code: randomCode,
        expiresAt,
      });

      // Send verification email to the user
      sendCodeEmail(email, randomCode);

      // Respond with success message
      res.status(200).json({ message: "Verification code sent successfully!" });
    });
  } catch (err) {
    // Handle unexpected errors
    console.error("Error in /api/enter:", err);
    res.status(500).json({ message: "An internal server error occurred." });
  }
});

// API route for completing user registration (Step 2: Verify code and store user)
app.post('/api/enter/end', async (req, res) => {
  const { code, email } = req.body;

  try {
    // Find the user entry in the temporary storage
    const userEntry = Array.from(signinStorage.entries()).find(
      ([_, value]) => String(value.email) === String(email) 
    );

    if (!userEntry) {
      // If no matching email is found, return an error
      return res.status(400).json({ message: "User not found or invalid email." });
    }

    const [_, userStorage] = userEntry;

    // Check if the entered code matches the stored code
    if (Number(userStorage.code) !== Number(code)) {
      return res.status(400).json({ message: "Invalid code entered." });
    }

    // Check if the verification code has expired
    if (Date.now() > new Date(userStorage.expiresAt).getTime()) {
      signinStorage.delete(email); // Remove expired data from storage
      return res.status(400).json({ message: "The verification code has expired." });
    }

    // Prepare the new user object for database insertion
    const newUser = {
      name: userStorage.name,
      email: userStorage.email,
      password: userStorage.password,
      birthyear: userStorage.birthyear,
    };

    // Insert the new user into the database
    const insertQuery = 'INSERT INTO users (name, email, password, birthyear) VALUES (?, ?, ?, ?)';
    const values = [userStorage.name, userStorage.email, userStorage.password, userStorage.birthyear];

    // Remove user data from temporary storage after insertion
    signinStorage.delete(email);

    db.query(insertQuery, values, (err, results) => {
      if (err) {
        console.error("SQL Error:", err.message); // Log SQL error
        return res.status(500).json({ message: 'Error adding user. ' + err.message });
      }

      // Respond with success message
      res.status(201).json({ message: 'User added successfully.' });
    });
  } catch (err) {
    // Handle unexpected errors
    res.status(500).json({ message: `Error occurred: ${err.message}` });
  }
});



// Handles login requests
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  // SQL query to find the user by email
  const query = 'SELECT * FROM users WHERE email = ?';

  db.query(query, [email], async (err, results) => {
    // Check for database query errors
    if (err) {
      return res.status(500).json({ message: 'Database query error.' });
    }

    // Verify if the user exists
    if (results.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const user = results[0]; // Retrieve the user data from the database

    // Check if the hashed password matches the provided password
    const isMatch = await bcrypt.compare(password, user.password);

    // Respond based on password match result
    if (isMatch) {
      res.status(200).json({ message: 'Login successful!' });
    } else {
      res.status(400).json({ message: 'Invalid password.' });
    }
  });
});



// Handles the first step of password recovery
app.post('/api/recovery/password/first', async (req, res) => {
  const { email } = req.body;

  // Query to check if the user with the provided email exists
  const checkQuery = 'SELECT * FROM users WHERE email = ?';
  db.query(checkQuery, [email], async (err, results) => {
    // Check for database query errors
    if (err) {
      console.error(err.message);
      return res.status(500).json({ message: 'Error checking user email.' });
    }

    // Verify if the email exists in the database
    if (results.length === 0) {
      return res.status(400).json({ message: 'Email not registered.' });
    }

    // Generate a random verification code and set expiration time
    const randomCode = Math.floor(Math.random() * 999999) + 1;
    const expiresAt = Date.now() + 15 * 60 * 1000; // Set to expire in 15 minutes

    // Store the verification code and email in memory
    forgetStorage.set(email, { email, code: randomCode, expiresAt });

    try {
      // Send the recovery email to the user
      await sendCodeEmail(email, randomCode);
      res.status(200).json({ message: 'Password recovery code sent successfully!' });
    } catch (err) {
      res.status(500).json({ message: err.message });
    }
  });
});

// Handles the second step of password recovery (verification of code)
app.post('/api/recovery/password/second', async (req, res) => {
  const { code, email } = req.body;

  // Find the user's entry in the recovery storage
  const userEntry = Array.from(forgetStorage.entries()).find(
    ([_, value]) => String(value.email) === String(email)
  );

  // Check if the entry exists in storage
  if (!userEntry) {
    return res.status(400).json({ message: 'Invalid recovery code entered.' });
  }

  const [_, userStorage] = userEntry;

  // Verify if the entered code matches the stored code
  if (Number(userStorage.code) !== Number(code)) {
    return res.status(400).json({ message: 'Invalid code entered.' });
  }

  // Check if the code has expired
  if (Date.now() > userStorage.expiresAt) {
    return res.status(400).json({ message: 'The recovery code has expired.' });
  }

  // If verification is successful, return a success message
  res.status(200).json({ message: 'Code successfully verified!', email });
});

// Handles the third step of password recovery (password update)
app.post('/api/recovery/password/third', async (req, res) => {
  const { password, email } = req.body;

  // Check if both password and email are provided
  if (!password || !email) {
    return res.status(400).json({ message: 'Password and email are required.' });
  }

  try {
    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // SQL query to update the user's password in the database
    const query = 'UPDATE users SET password = ? WHERE email = ?';
    const values = [hashedPassword, email];

    // Execute the query to update the password
    const result = await db.execute(query, values);

    // Check if the password was successfully updated
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'No user found with the provided email.' });
    }

    // Remove the user's recovery entry from storage
    forgetStorage.delete(email);
    res.status(200).json({ message: 'Password successfully updated!' });
  } catch (error) {
    console.error('Error updating password:', error);
    res.status(500).json({ message: 'An error occurred while updating the password.' });
  }
});



// Handles assigning or revoking the "moderator" role for a user
app.post('/api/tier/moderator/giveRetract', async (req, res) => {
  // Extracts email, tier, and purpose from the request body
  const { email, tier, purpose } = req.body;

  // Validates the incoming request body using Joi
  const schema = Joi.object({
    email: Joi.string().email().required().messages({
      'string.email': '"email" must be a valid email address.',
      'any.required': '"email" is required.',
    }),
    tier: Joi.string().valid('customer', 'seller', 'moderator', 'admin').required().messages({
      'any.only': '"tier" must be one of "customer", "seller", "moderator", or "admin".',
      'any.required': '"tier" is required.',
    }),
    purpose: Joi.string().valid('give', 'retract').required().messages({
      'string.min': '"purpose" must have at least 5 characters.',
      'any.required': '"purpose" is required.',
    }),
  });

  // Checks for validation errors
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  // Finds the user by their email in the database
  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Database query error.' });
    }

    // Returns a 404 error if the user is not found
    if (results.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const user = results[0]; // Retrieves the first result since email should be unique

    if (purpose === 'retract') {
      // Validates that the user is currently a moderator
      if (user.usertier !== 'moderator') {
        return res.status(400).json({ message: 'User is not a moderator.' });
      }

      // Updates the user's tier in the database
      const updateQuery = 'UPDATE users SET usertier = ? WHERE email = ?';
      db.query(updateQuery, [tier, email], (err) => {
        if (err) {
          return res.status(500).json({ message: 'Error retracting moderator status.' });
        }

        res.status(200).json({ message: 'User tier retracted successfully.' });
      });

    } else if (purpose === 'give') {
      // Ensures the user is not already a moderator
      if (user.usertier === 'moderator') {
        return res.status(400).json({ message: 'User is already a moderator.' });
      }

      // Updates the user's tier to moderator
      const updateQuery = 'UPDATE users SET usertier = ? WHERE email = ?';
      db.query(updateQuery, [tier, email], (err) => {
        if (err) {
          return res.status(500).json({ message: 'Error updating user as moderator.' });
        }

        res.status(200).json({ message: 'User updated as moderator successfully.' });
      });
    } else {
      // Handles invalid purpose values
      return res.status(400).json({ message: 'Invalid purpose provided. It should be "give" or "retract".' });
    }
  });
});

// Handles assigning or revoking the "seller" role for a user
app.post('/api/tier/seller/giveRetract', async (req, res) => {
  const { email, tier, purpose } = req.body;

  // Validates the request body
  const schema = Joi.object({
    email: Joi.string().email().required().messages({
      'string.email': '"email" must be a valid email address.',
      'any.required': '"email" is required.',
    }),
    tier: Joi.string().valid('customer', 'seller', 'moderator', 'admin').required().messages({
      'any.only': '"tier" must be one of "customer", "seller", "moderator", or "admin".',
      'any.required': '"tier" is required.',
    }),
    purpose: Joi.string().min(4).required().messages({
      'string.min': '"purpose" must have at least 5 characters.',
      'any.required': '"purpose" is required.',
    }),
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Database query error.' });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const user = results[0];

    if (purpose === 'retract') {
      if (user.usertier !== 'seller') {
        return res.status(400).json({ message: 'User is not a seller.' });
      }

      const updateQuery = 'UPDATE users SET usertier = ? WHERE email = ?';
      db.query(updateQuery, [tier, email], (err) => {
        if (err) {
          return res.status(500).json({ message: 'Error retracting seller status.' });
        }

        res.status(200).json({ message: 'User tier retracted successfully.' });
      });

    } else if (purpose === 'give') {
      if (user.usertier === 'seller') {
        return res.status(400).json({ message: 'User is already a seller.' });
      }

      const updateQuery = 'UPDATE users SET usertier = ? WHERE email = ?';
      db.query(updateQuery, [tier, email], (err) => {
        if (err) {
          return res.status(500).json({ message: 'Error updating user as seller.' });
        }

        res.status(200).json({ message: 'User updated as seller successfully.' });
      });
    } else {
      return res.status(400).json({ message: 'Invalid purpose provided. It should be "give" or "retract".' });
    }
  });
});




app.get('/api/information/get/:email', async (req, res) => {
  try {
    const { email } = req.params; // Get the email from the user

    // Email validation
    if (!email) {
      return res.status(400).json({ message: "Email is required." });
    }

    // SQL query to find the user by email
    const query = 'SELECT * FROM users WHERE email = ?';

    db.query(query, [email], (err, results) => {
      if (err) {
        console.error('Database query error:', err);
        return res.status(500).json({ message: 'Database query error.' });
      }

      if (results.length === 0) {
        return res.status(404).json({ message: 'User not found.' });
      }

      // Get the user data
      const user = results[0]; // Take the first result

      // Calculate age
      const currentYear = new Date().getFullYear();
      const age = user.birthyear ? currentYear - user.birthyear : "Unknown";

      // Prepare the profile data
      const profileData = {
        name: user.name || "No name provided",
        email: user.email,
        age,
      };

      // Send the response
      res.status(200).json(profileData);
    });
  } catch (err) {
    // Log errors and send an error response
    console.error("Error fetching profile:", err);
    res.status(500).json({ message: `Error: ${err.message}` });
  }
});

app.put('/api/information/update', async (req, res) => {
  const { email, name, birthyear } = req.body;

  // Validate the request body
  const schema = Joi.object({
    email: Joi.string().email().required().messages({
      'string.email': '"email" must be a valid email address.',
      'any.required': '"email" is required.',
    }),
    name: Joi.string().min(2).required().messages({
      'string.min': '"name" must have at least 2 characters.',
      'any.required': '"name" is required.',
    }),
    birthyear: Joi.number().integer().min(1900).max(new Date().getFullYear()).required().messages({
      'number.base': '"birthyear" must be a number.',
      'number.min': '"birthyear" must be greater than or equal to 1900.',
      'number.max': `"birthyear" must be less than or equal to ${new Date().getFullYear()}.`,
      'any.required': '"birthyear" is required.',
    }),
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  // SQL query to update the user information
  const query = 'UPDATE users SET name = ?, birthyear = ? WHERE email = ?';

  db.query(query, [name, birthyear, email], (err, results) => {
    if (err) {
      console.error('Error updating user:', err);
      return res.status(500).json({ message: 'Error updating user. Please try again later.' });
    }

    if (results.affectedRows === 0) {
      return res.status(404).json({ message: 'User not found.' }); // No user updated
    }

    res.status(200).json({ message: 'User information updated successfully.' });
  });
});

app.delete('/api/information/delete', async (req, res) => {
  const { email } = req.body;

  // Validate the request body
  const schema = Joi.object({
    email: Joi.string().email().required().messages({
      'string.email': '"email" must be a valid email address.',
      'any.required': '"email" is required.',
    }),
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  // SQL query to delete the user
  const query = 'DELETE FROM users WHERE email = ?';

  db.query(query, [email], (err, results) => {
    if (err) {
      console.error('Error deleting user:', err);
      return res.status(500).json({ message: 'Error deleting user. Please try again later.' });
    }

    if (results.affectedRows === 0) {
      return res.status(404).json({ message: 'User not found.' }); // No user deleted
    }

    res.status(200).json({ message: 'User deleted successfully.' });
  });
});




// POST endpoint to add a new category
app.post('/api/category/add', async (req, res) => {
  const { name, description } = req.body;

  // Validate the request body using Joi schema
  const schema = Joi.object({
    name: Joi.string().min(2).required().messages({
      'string.base': '"name" must be a string.',
      'string.min': '"name" must have at least 2 characters.',
      'any.required': '"name" is required.',
    }),
    description: Joi.string().min(8).required().messages({
      'string.base': '"description" must be a string.',
      'string.min': '"description" must have at least 8 characters.',
      'any.required': '"description" is required.',
    }),
  });

  // Validate request and handle error if validation fails
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    // Check if the category already exists
    const existingCategory = await new Promise((resolve, reject) => {
      db.query('SELECT * FROM categories WHERE name = ?', [name], (err, results) => {
        if (err) return reject(err);
        resolve(results[0]);
      });
    });

    // If category exists, return a conflict response
    if (existingCategory) {
      return res.status(409).json({ message: 'Category name already exists.' });
    }

    // Insert the new category into the database
    const query = `INSERT INTO categories (name, description) VALUES (?, ?)`;
    const values = [name, description];
    const insertResult = await new Promise((resolve, reject) => {
      db.query(query, values, (err, results) => {
        if (err) return reject(err);
        resolve(results);
      });
    });

    // Respond with success and the ID of the newly added category
    res.status(201).json({
      message: 'Category added successfully.',
      categoryId: insertResult.insertId,
    });
  } catch (err) {
    console.error('Error adding category:', err);
    res.status(500).json({ message: 'An error occurred. Please try again later.' });
  }
});

// DELETE endpoint to delete a category
app.delete('/api/category/delete', async (req, res) => {
  const { name } = req.body;

  // Validate the request body using Joi schema
  const schema = Joi.object({
    name: Joi.string().min(2).required().messages({
      'string.base': '"name" must be a string.',
      'string.min': '"name" must have at least 2 characters.',
      'any.required': '"name" is required.',
    }),
  });

  // Validate request and handle error if validation fails
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  // SQL query to delete the category
  const query = 'DELETE FROM categories WHERE name = ?';
  db.query(query, [name], (err, results) => {
    if (err) {
      console.error('Error deleting category:', err);
      return res.status(500).json({ message: 'Error deleting category. Please try again later.' });
    }

    // If no rows were affected, the category does not exist
    if (results.affectedRows === 0) {
      return res.status(404).json({ message: 'Category not found.' });
    }

    // Respond with success if category is deleted
    res.status(200).json({ message: 'Category deleted successfully.' });
  });
});

// PUT endpoint to update an existing category
app.put('/api/category/update', async (req, res) => {
  const { name, description } = req.body;

  // Validate the request body using Joi schema
  const schema = Joi.object({
    name: Joi.string().min(2).required().messages({
      'string.base': '"name" must be a string.',
      'string.min': '"name" must have at least 2 characters.',
      'any.required': '"name" is required.',
    }),
    description: Joi.string().min(5).required().messages({
      'string.base': '"description" must be a string.',
      'string.min': '"description" must have at least 5 characters.',
      'any.required': '"description" is required.',
    }),
  });

  // Validate request and handle error if validation fails
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  // SQL query to update the category
  const query = `UPDATE categories SET name = ?, description = ? WHERE name = ?`;
  const values = [name, description, name];
  db.query(query, values, (err, results) => {
    if (err) {
      console.error('Error updating category:', err);
      return res.status(500).json({ message: 'Error updating category. Please try again later.' });
    }

    // If no rows were affected, the category does not exist
    if (results.affectedRows === 0) {
      return res.status(404).json({ message: 'Category not found.' });
    }

    // Respond with success if category is updated
    res.status(200).json({ message: 'Category updated successfully.' });
  });
});

// GET endpoint to retrieve a category
app.get('/api/category/get/:name', async (req, res) => {
  const { name } = req.params;

  // Validate the request body using Joi schema
  const schema = Joi.object({
    name: Joi.string().min(2).required().messages({
      'string.base': '"name" must be a string.',
      'string.min': '"name" must have at least 2 characters.',
      'any.required': '"name" is required.',
    }),
  });

  // Validate request and handle error if validation fails
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  // SQL query to get the category by name
  const query = 'SELECT * FROM categories WHERE name = ?';
  db.query(query, [name], (err, results) => {
    if (err) {
      console.error('Error fetching category:', err);
      return res.status(500).json({ message: 'Error fetching category. Please try again later.' });
    }

    // If category is not found, return a 404 error
    if (results.length === 0) {
      return res.status(404).json({ message: 'Category not found.' });
    }

    // Prepare the category data to send back in the response
    const category = results[0];
    const categoryData = {
      id: category.idcategories,
      name: category.name,
      description: category.description,
    };

    // Send the category data as a response
    res.status(200).json(categoryData);
  });
});




app.post('/api/cart/add', async (req, res) => { 
  const { idcustomer, idorder, newQuantity } = req.body;

  // Validate the request body: Ensure 'idcustomer', 'idorder', and 'newQuantity' are valid numbers
  const schema = Joi.object({
    idcustomer: Joi.number().integer().min(1).required().messages({
      'number.base': '"idcustomer" must be a number.',
      'number.min': '"idcustomer" must be greater than or equal to 1.',
      'any.required': '"idcustomer" is required.',
    }),
    idorder: Joi.number().integer().min(1).required().messages({
      'number.base': '"idorder" must be a number.',
      'number.min': '"idorder" must be greater than or equal to 1.',
      'any.required': '"idorder" is required.',
    }),
    newQuantity: Joi.number().integer().min(0).required().messages({
      'number.base': '"newQuantity" must be a number.',
      'number.min': '"newQuantity" must be greater than or equal to 0.',
      'any.required': '"newQuantity" is required.',
    }),
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    // Fetch product details to check stock quantity
    const productResults = await new Promise((resolve, reject) => {
      db.query('SELECT * FROM products WHERE idproducts = ?', [idorder], (err, results) => {
        if (err) return reject(err);
        resolve(results);
      });
    });

    // If no product is found, return 404 error
    if (productResults.length === 0) {
      return res.status(404).json({ message: 'Product not found.' });
    }

    const product = productResults[0];

    // If requested quantity exceeds stock, return error
    if (newQuantity > product.quantity) {
      return res.status(400).json({ message: 'Not enough quantity in stock.' });
    }

    // Fetch the customer's current cart data
    const query = 'SELECT cart FROM users WHERE id = ?';
    const [customerData] = await db.promise().query(query, [idcustomer]);

    // If customer not found, return 404 error
    if (customerData.length === 0) {
      return res.status(404).json({ message: 'Customer not found.' });
    }

    // Parse the cart data
    let cart = [];
    try {
      cart = customerData[0].cart || [];
    } catch (parseError) {
      console.error('Error parsing cart JSON:', parseError);
      return res.status(500).json({ message: 'Invalid cart data. Please contact support.' });
    }

    // Try to find the order in the cart and update its quantity
    let orderFound = false;
    let updatedCart = cart.map(item => {
      if (item.productId === idorder) {
        orderFound = true;
        return { ...item, quantity: newQuantity };
      }
      return item;
    });

    // If the item was not found in the cart, add it
    if (!orderFound) {
      const newItem = JSON.stringify({ productId: idorder, quantity: newQuantity });
      const values = [newItem, idcustomer];

      const query = `
        UPDATE users
        SET cart = JSON_ARRAY_APPEND(cart, '$', CAST(? AS JSON))
        WHERE id = ?;
      `;

      // Update the cart with the new item
      const updateResult = await new Promise((resolve, reject) => {
        db.query(query, values, (err, results) => {
          if (err) return reject(err);
          resolve(results);
        });
      });

      // If the update failed, return an error
      if (updateResult.affectedRows === 0) {
        return res.status(500).json({ message: 'Failed to add item to the cart.' });
      }

      res.status(201).json({
        message: 'Item added to the cart successfully.',
      });
    } else {
      // If the item is found, update the cart and save changes to the database
      const updateQuery = 'UPDATE users SET cart = ? WHERE id = ?';
      await db.promise().query(updateQuery, [JSON.stringify(updatedCart), idcustomer]);

      res.status(200).json({
        message: 'Order updated successfully.',
        cart: updatedCart, // Return the updated cart
      });
    }
  } catch (err) {
    console.error('Error processing request:', err);
    res.status(500).json({ message: 'An error occurred while processing the request. Please try again later.' });
  }
});

// Endpoint to fetch a customer's cart or a specific order from the cart
app.get('/api/cart/get/oneAll/:idcustomer/:idorder/:purpose', async (req, res) => {
  // Destructuring the values from the request body
  const { idcustomer, idorder, purpose } = req.params;

  // Validate the request body with Joi
  const schema = Joi.object({
    // Purpose must be either 'one' or 'all'
    purpose: Joi.string().valid('one', 'all').required().messages({
      'any.only': '"purpose" must be one of "one" or "all".',
      'any.required': '"purpose" is required.',
    }),
    // idorder is required if purpose is 'one', forbidden for 'all'
    idorder: Joi.number().integer().min(1).when('purpose', {
      is: 'one',
      then: Joi.required(),
      otherwise: Joi.forbidden(),
    }).messages({
      'number.base': '"orderId" must be a number.',
      'number.min': '"orderId" must be greater than or equal to 1.',
      'any.required': '"orderId" is required.',
    }),
    // idcustomer must be a valid number
    idcustomer: Joi.number().integer().min(1).required().messages({
      'number.base': '"customerId" must be a number.',
      'number.min': '"customerId" must be greater than or equal to 1.',
      'any.required': '"customerId" is required.',
    }),
  });

  // Validate the input parameters against the schema
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    if (purpose === 'all') {
      // Query to fetch the customer's cart
      const query = 'SELECT cart FROM users WHERE id = ?';
      const [customerData] = await db.promise().query(query, [idcustomer]);

      if (customerData.length === 0) {
        return res.status(404).json({ message: 'Customer not found.' });
      }

      // Parse the cart data
      let cart = [];
      try {
        const cartData = customerData[0].cart;
        console.log(cartData);
        cart = cartData; // Assuming cart is stored as JSON string
      } catch (parseError) {
        console.warn('Invalid JSON in cart data:', parseError);
        cart = []; // Reset to empty array if invalid JSON
      }

      // Return the entire cart data
      res.status(200).json({
        message: 'Cart retrieved successfully.',
        cart: cart,
      });
    } else if (purpose === 'one') {
      // Query to fetch the customer's cart
      const query = 'SELECT cart FROM users WHERE id = ?';
      const [customerData] = await db.promise().query(query, [idcustomer]);

      if (customerData.length === 0) {
        return res.status(404).json({ message: 'Customer not found.' });
      }

      // Parse the cart data
      let cart = [];
      try {
        const cartData = customerData[0].cart;
        console.log(cartData);
        cart = cartData; // Assuming cart is stored as JSON string
      } catch (parseError) {
        console.warn('Invalid JSON in cart data:', parseError);
        cart = []; // Reset to empty array if invalid JSON
      }

      // Find the specific order from the cart
      const order = cart.find(item => item.productId === idorder);

      if (!order) {
        return res.status(404).json({ message: 'Order not found.' });
      }

      // Return the specific order data
      res.status(200).json({
        message: 'Order retrieved successfully.',
        order: order,
      });
    }
  } catch (err) {
    // Error handling
    console.error('Error fetching cart:', err);
    res.status(500).json({ message: 'An error occurred while fetching the cart. Please try again later.' });
  }
});

// Endpoint to delete an order or clear the entire cart
app.delete('/api/cart/delete/oneAll', async (req, res) => {
  const { idcustomer, idorder, purpose } = req.body;

  // Validate the request body with Joi
  const schema = Joi.object({
    // Purpose must be either 'one' or 'all'
    purpose: Joi.string().valid('one', 'all').required().messages({
      'any.only': '"purpose" must be one of "one" or "all".',
      'any.required': '"purpose" is required.',
    }),
    // idorder is required if purpose is 'one', forbidden for 'all'
    idorder: Joi.number().integer().min(1).when('purpose', {
      is: 'one',
      then: Joi.required(),
      otherwise: Joi.forbidden(),
    }).messages({
      'number.base': '"idorder" must be a number.',
      'number.min': '"idorder" must be greater than or equal to 1.',
      'any.required': '"idorder" is required.',
    }),
    // idcustomer must be a valid number
    idcustomer: Joi.number().integer().min(1).required().messages({
      'number.base': '"idcustomer" must be a number.',
      'number.min': '"idcustomer" must be greater than or equal to 1.',
      'any.required': '"idcustomer" is required.',
    }),
  });

  // Validate the input parameters against the schema
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    if (purpose === 'all') {
      // Query to clear the entire cart
      const query = 'UPDATE users SET cart = ? WHERE id = ?';
      const result = await db.promise().query(query, [JSON.stringify([]), idcustomer]);

      if (result.affectedRows === 0) {
        return res.status(404).json({ message: 'Customer not found.' });
      }

      // Return success message after clearing cart
      res.status(200).json({
        message: 'Cart cleared successfully.',
      });
    } else if (purpose === 'one') {
      // Query to fetch the customer's cart
      const query = 'SELECT cart FROM users WHERE id = ?';
      const [customerData] = await db.promise().query(query, [idcustomer]);

      if (customerData.length === 0) {
        return res.status(404).json({ message: 'Customer not found.' });
      }

      // Parse the cart data
      let cart = [];
      try {
        cart = customerData[0].cart;
      } catch (parseError) {
        console.error('Error parsing cart JSON:', parseError);
        return res.status(500).json({ message: 'Invalid cart data. Please contact support.' });
      }

      // Find and remove the specific order from the cart
      const updatedCart = cart.filter(item => item.productId !== idorder);

      // If no change occurred (i.e., the item was not found)
      if (updatedCart.length === cart.length) {
        return res.status(404).json({ message: 'Order not found in cart.' });
      }

      // Update the cart in the database
      const updateQuery = 'UPDATE users SET cart = ? WHERE id = ?';
      await db.promise().query(updateQuery, [JSON.stringify(updatedCart), idcustomer]);

      // Return success message after removing the order
      res.status(200).json({
        message: 'Order removed successfully.',
        cart: updatedCart, // Return the updated cart
      });
    }
  } catch (err) {
    // Error handling
    console.error('Error processing request:', err);
    res.status(500).json({ message: 'An error occurred while processing the request. Please try again later.' });
  }
});

// Endpoint to update a product's quantity in a customer's cart
app.put('/api/cart/update', async (req, res) => {
  const { idcustomer, idorder, newQuantity } = req.body;

  // Validate the incoming request body using Joi
  const schema = Joi.object({
    idcustomer: Joi.number().integer().min(1).required().messages({
      'number.base': '"idcustomer" must be a number.',
      'number.min': '"idcustomer" must be greater than or equal to 1.',
      'any.required': '"idcustomer" is required.',
    }),
    idorder: Joi.number().integer().min(1).required().messages({
      'number.base': '"idorder" must be a number.',
      'number.min': '"idorder" must be greater than or equal to 1.',
      'any.required': '"idorder" is required.',
    }),
    newQuantity: Joi.number().integer().min(0).required().messages({
      'number.base': '"newQuantity" must be a number.',
      'number.min': '"newQuantity" must be greater than or equal to 0.',
      'any.required': '"newQuantity" is required.',
    }),
  });

  // Validate request data and return error if invalid
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    // Query to check the availability of the product in stock
    const productResults = await new Promise((resolve, reject) => {
      db.query('SELECT * FROM products WHERE idproducts = ?', [idorder], (err, results) => {
        if (err) return reject(err);
        resolve(results);
      });
    });

    const product = productResults[0];

    // Check if the requested quantity exceeds available stock
    if (newQuantity > product.quantity) {
      return res.status(400).json({ message: 'Not enough quantity in stock.' });
    }

    // SQL query to fetch the customer's cart data from the database
    const query = 'SELECT cart FROM users WHERE id = ?';
    const [customerData] = await db.promise().query(query, [idcustomer]);

    // Return error if the customer is not found
    if (customerData.length === 0) {
      return res.status(404).json({ message: 'Customer not found.' });
    }

    // Parse the customer's cart data
    let cart = [];
    try {
      cart = customerData[0].cart || '[]';
    } catch (parseError) {
      console.error('Error parsing cart JSON:', parseError);
      return res.status(500).json({ message: 'Invalid cart data. Please contact support.' });
    }

    // Find and update the specific product in the cart based on order ID
    let orderFound = false;
    const updatedCart = cart.map(item => {
      if (item.productId === idorder) {
        orderFound = true;
        return { ...item, quantity: newQuantity };
      }
      return item;
    });

    // Return error if the order was not found in the cart
    if (!orderFound) {
      return res.status(404).json({ message: 'Order not found in cart.' });
    }

    // Update the cart in the database with the new quantity
    const updateQuery = 'UPDATE users SET cart = ? WHERE id = ?';
    await db.promise().query(updateQuery, [JSON.stringify(updatedCart), idcustomer]);

    // Respond with the updated cart and success message
    res.status(200).json({
      message: 'Order updated successfully.',
      cart: updatedCart, // Return the updated cart
    });
  } catch (err) {
    // Handle any errors that occur during the request processing
    console.error('Error processing request:', err);
    res.status(500).json({ message: 'An error occurred while processing the request. Please try again later.' });
  }
});



// Function to insert a new order into the 'orders' table
const insertOrder = async (db, idcustomer, cartItems) => { 
  return new Promise((resolve, reject) => {
    // SQL query to insert a new order
    const insertQuery = `
    INSERT INTO orders (idcustomer, \`order\`)
    VALUES (?, ?);
  `;
    // Execute the query to insert the order
    db.query(insertQuery, [idcustomer, JSON.stringify(cartItems)], (err, results) => {
      if (err) return reject(err); // Reject if there is an error
      resolve(results); // Resolve if successful
    });
  });
};

// Function to process the customer's cart and convert it into an order
const processCartToOrder = async (db, req, res) => {
  const { idcustomer } = req.body;

  // Validate the request body with Joi
  const schema = Joi.object({
    idcustomer: Joi.number().integer().min(1).required().messages({
      'number.base': '"idcustomer" must be a number.',
      'number.min': '"idcustomer" must be greater than or equal to 1.',
      'any.required': '"idcustomer" is required.',
    }),
      currency: Joi.string().length(3).optional(), // Optional currency field
      description: Joi.string().min(8).optional(), // Optional description field
      promotionCode: Joi.string().min(8).optional(), // Optional promotion code field
  });

  // If request body is invalid, return an error
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    // SQL query to fetch the customer's cart
    const query = 'SELECT cart FROM users WHERE id = ?';
    const [customerData] = await db.promise().query(query, [idcustomer]);

    // If the customer is not found, return an error
    if (customerData.length === 0) {
      return res.status(404).json({ message: 'Customer not found.' });
    }

    // Parse the cart data stored as a JSON string
    let cart = [];
    try {
      cart = customerData[0].cart; // Assuming cart is stored as a JSON string
    } catch (parseError) {
      console.warn('Invalid JSON in cart data:', parseError);
      return res.status(400).json({ message: 'Invalid cart data.' });
    }

    // If the cart is empty, return an error
    if (cart.length === 0) {
      return res.status(400).json({ message: 'Cart is empty.' });
    }

    const updatedCart = [];
    let total_amount = 0;

    // Process each item in the cart
    for (const item of cart) {
      const idproduct = item.productId;
      const quantity = item.quantity;
      let newItemPiece = JSON.stringify({ productId: idproduct, quantity: quantity });

      // Fetch product details from the database
      const productResults = await new Promise((resolve, reject) => {
        db.query('SELECT * FROM products WHERE idproducts = ?', [idproduct], (err, results) => {
          if (err) return reject(err);
          resolve(results);
        });
      });

      // If the product is not found, return an error
      if (productResults.length === 0) {
        return res.status(404).json({ message: `Product with ID ${idproduct} not found.` });
      }

      const product = productResults[0];

      // Update total order amount
      total_amount += product.price * quantity;

      // Check if there is enough stock for the requested quantity
      if (quantity > product.quantity) {
        return res.status(400).json({
          message: `Not enough quantity in stock for product ID ${idproduct}.`,
        });
      }

      // Update the product quantity in stock
      const newQuantity = product.quantity - quantity;

      await new Promise((resolve, reject) => {
        db.query(
          'UPDATE products SET quantity = ? WHERE idproducts = ?',
          [newQuantity, idproduct],
          (err, results) => {
            if (err) return reject(err);
            resolve(results);
          }
        );
      });

      updatedCart.push(newItemPiece); // Add the processed item to the updated cart
    }

    // Insert the processed order into the database
    await insertOrder(db, idcustomer, updatedCart);

    // Clear the cart after processing the order
    await db.promise().query('UPDATE users SET cart = ? WHERE id = ?', ["[]", idcustomer]);

    // Optional: Return a success message after processing the order
    // res.status(201).json({ message: 'All items in the cart have been processed into orders successfully.' });

  } catch (err) {
    // Handle any errors that occur during the process
    console.error('Error processing request:', err);
    res.status(500).json({ message: 'An error occurred while processing the request. Please try again later.' });
  }
};

// POST route to trigger the processCartToOrder function
app.post('/api/process-cart', async (req, res) => {
  try {
    // Call the function to process the cart and convert it into an order
    await processCartToOrder(db, req, res);
  } catch (error) {
    // Handle any unexpected errors in the API route
    console.error('Error in API route:', error);
    res.status(500).json({
      message: 'An unexpected error occurred. Please try again later.',
    });
  }
});




// Route to add a new product to the database
app.post('/api/product/add', async (req, res) => { 
  const { idseller, category, name, price, description, quantity } = req.body;

  // Validate the request body using Joi schema
  const schema = Joi.object({
    idseller: Joi.number().integer().min(0).required()
      .messages({
        'number.base': '"idseller" must be a number.',
        'number.min': '"idseller" must be greater than or equal to 0.',
        'any.required': '"idseller" is required.',
      }),
    category: Joi.string().min(2).required()
      .messages({
        'string.base': '"category" must be a string.',
        'string.min': '"category" must have at least 2 characters.',
        'any.required': '"category" is required.',
      }),
    name: Joi.string().min(2).required()
      .messages({
        'string.base': '"name" must be a string.',
        'string.min': '"name" must have at least 2 characters.',
        'any.required': '"name" is required.',
      }),
    price: Joi.number().min(0).required()
      .messages({
        'number.base': '"price" must be a number.',
        'number.min': '"price" must be greater than or equal to 0.',
        'any.required': '"price" is required.',
      }),
    description: Joi.string().min(5).required()
      .messages({
        'string.base': '"description" must be a string.',
        'string.min': '"description" must have at least 5 characters.',
        'any.required': '"description" is required.',
      }),
    quantity: Joi.number().integer().min(1).required()
      .messages({
        'number.base': '"quantity" must be a number.',
        'number.min': '"quantity" must be greater than or equal to 1.',
        'any.required': '"quantity" is required.',
      }),
  });

  // Validate input based on the schema
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  // Query to check if the category exists in the database
  const query1 = 'SELECT * FROM categories WHERE name = ?';

  db.query(query1, [category], (err, results) => {
    if (err) {
      console.error('Error fetching category:', err);
      return res.status(500).json({ message: 'Error fetching category. Please try again later.' });
    }

    // If the category is not found, return an error
    if (results.length === 0) {
      return res.status(404).json({ message: 'Category not found.' });
    }
  });

  // SQL query to insert the new product into the database
  const query = `
    INSERT INTO products (idseller, category, name, price, description, quantity)
    VALUES (?, ?, ?, ?, ?, ?)
  `;
  const values = [idseller, category, name, price, description, quantity];

  db.query(query, values, (err, results) => {
    if (err) {
      console.error('Error adding product:', err);
      return res.status(500).json({ message: 'Error adding product. Please try again later.' });
    }

    // Return the newly created product ID
    res.status(201).json({
      message: 'Product added successfully.',
      productId: results.insertId,
    });
  });
});

// Route to fetch a product by its ID
app.get('/api/product/get/:productId', async (req, res) => {
  const { productId } = req.params;

  // Validate the productId in the request body
  const schema = Joi.object({
    productId: Joi.number().integer().min(1).required()
      .messages({
        'number.base': '"productId" must be a number.',
        'number.min': '"productId" must be greater than or equal to 1.',
        'any.required': '"productId" is required.',
      }),
  });

  // Validate input based on the schema
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  // SQL query to retrieve the product by ID
  const query = 'SELECT * FROM products WHERE idproducts = ?';

  db.query(query, [productId], (err, results) => {
    if (err) {
      console.error('Error fetching product:', err);
      return res.status(500).json({ message: 'Error fetching product. Please try again later.' });
    }

    // If the product is not found, return an error
    if (results.length === 0) {
      return res.status(404).json({ message: 'Product not found.' });
    }

    const product = results[0];

    // Optional: Format or add additional details if needed
    const productData = {
      id: product.id,
      name: product.name,
      category: product.category,
      price: product.price,
      description: product.description,
      quantity: product.quantity,
    };

    // Send the product data in the response
    res.status(200).json(productData);
  });
});

// Route to update a product's information
app.put('/api/product/update', async (req, res) => {
  const { productId, category, name, price, description, quantity } = req.body;

  // Validate the request body using Joi schema
  const schema = Joi.object({
    productId: Joi.number().integer().min(1).required()
      .messages({
        'number.base': '"productId" must be a number.',
        'number.min': '"productId" must be greater than or equal to 1.',
        'any.required': '"productId" is required.',
      }),
    category: Joi.string().min(2).required()
      .messages({
        'string.base': '"category" must be a string.',
        'string.min': '"category" must have at least 2 characters.',
        'any.required': '"category" is required.',
      }),
    name: Joi.string().min(2).required()
      .messages({
        'string.base': '"name" must be a string.',
        'string.min': '"name" must have at least 2 characters.',
        'any.required': '"name" is required.',
      }),
    price: Joi.number().min(0).required()
      .messages({
        'number.base': '"price" must be a number.',
        'number.min': '"price" must be greater than or equal to 0.',
        'any.required': '"price" is required.',
      }),
    description: Joi.string().min(5).required()
      .messages({
        'string.base': '"description" must be a string.',
        'string.min': '"description" must have at least 5 characters.',
        'any.required': '"description" is required.',
      }),
    quantity: Joi.number().integer().min(1).required()
      .messages({
        'number.base': '"quantity" must be a number.',
        'number.min': '"quantity" must be greater than or equal to 1.',
        'any.required': '"quantity" is required.',
      }),
  });

  // Validate input based on the schema
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  // SQL query to update the product in the database
  const query = `
    UPDATE products
    SET category = ?, name = ?, price = ?, description = ?, quantity = ?
    WHERE idproducts = ?
  `;
  const values = [category, name, price, description, quantity, productId];

  db.query(query, values, (err, results) => {
    if (err) {
      console.error('Error updating product:', err);
      return res.status(500).json({ message: 'Error updating product. Please try again later.' });
    }

    // If no product was updated, return an error
    if (results.affectedRows === 0) {
      return res.status(404).json({ message: 'Product not found.' });
    }

    // Return success message
    res.status(200).json({ message: 'Product updated successfully.' });
  });
});

// Route to delete a product from the database
app.delete('/api/product/delete', async (req, res) => {
  const { productId } = req.body;

  // Validate the productId in the request body
  const schema = Joi.object({
    productId: Joi.number().integer().min(1).required()
      .messages({
        'number.base': '"productId" must be a number.',
        'number.min': '"productId" must be greater than or equal to 1.',
        'any.required': '"productId" is required.',
      }),
  });

  // Validate input based on the schema
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  // SQL query to delete the product by ID
  const query = 'DELETE FROM products WHERE idproducts = ?';

  db.query(query, [productId], (err, results) => {
    if (err) {
      console.error('Error deleting product:', err);
      return res.status(500).json({ message: 'Error deleting product. Please try again later.' });
    }

    // If no product was deleted, return an error
    if (results.affectedRows === 0) {
      return res.status(404).json({ message: 'Product not found.' });
    }

    // Return success message
    res.status(200).json({ message: 'Product deleted successfully.' });
  });
});



app.post('/api/order/add', async (req, res) => { 
  const { idcustomer, idproduct, quantity } = req.body;

  // Validate the request body
  const schema = Joi.object({
    idcustomer: Joi.number().integer().min(1).required().messages({
      'number.base': '"idcustomer" must be a number.',
      'number.min': '"idcustomer" must be greater than or equal to 1.',
      'any.required': '"idcustomer" is required.',
    }),
    idproduct: Joi.number().integer().min(1).required().messages({
      'number.base': '"idproduct" must be a number.',
      'number.min': '"idproduct" must be greater than or equal to 1.',
      'any.required': '"idproduct" is required.',
    }),
    quantity: Joi.number().integer().min(1).required().messages({
      'number.base': '"quantity" must be a number.',
      'number.min': '"quantity" must be greater than or equal to 1.',
      'any.required': '"quantity" is required.',
    }),
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    // Fetch the product from the database
    const productResults = await new Promise((resolve, reject) => {
      db.query('SELECT * FROM products WHERE idproducts = ?', [idproduct], (err, results) => {
        if (err) return reject(err);
        resolve(results);
      });
    });

    if (productResults.length === 0) {
      return res.status(404).json({ message: 'Product not found.' });
    }

    const product = productResults[0];

    // Check if there is enough quantity in stock
    if (quantity > product.quantity) {
      return res.status(400).json({ message: 'Not enough quantity in stock.' });
    }

    // Add item to cart
    const insertQuery = `
      INSERT INTO orders (idcustomer, \`order\`)
      VALUES (?, ?);
    `;
    const newItem = JSON.stringify({ productId: idproduct, quantity: quantity });

    const insertResult = await new Promise((resolve, reject) => {
      db.query(insertQuery, [idcustomer, newItem], (err, results) => {
        if (err) return reject(err);
        resolve(results);
      });
    });

    if (insertResult.affectedRows === 0) {
      return res.status(500).json({ message: 'Failed to add item to the cart.' });
    }

    // Update the product quantity
    const newQuantity = product.quantity - quantity;

    await new Promise((resolve, reject) => {
      db.query(
        'UPDATE products SET quantity = ? WHERE idproducts = ?',
        [newQuantity, idproduct],
        (err, results) => {
          if (err) return reject(err);
          resolve(results);
        }
      );
    });

    // Only send a single response at the end
    res.status(201).json({
      message: 'Order added successfully.',
    });

  } catch (err) {
    console.error('Error processing request:', err);
    // Check if the headers are already sent before sending another response
    if (!res.headersSent) {
      return res.status(500).json({ message: 'An error occurred. Please try again later.' });
    }
  }
});

app.get('/api/order/get/oneAll/:customerId/:orderId/:purpose', async (req, res) => {
  const { customerId, orderId, purpose } = req.params;

  // Conditional validation with a single Joi schema
  const schema = Joi.object({
    purpose: Joi.string().valid('one', 'all').required().messages({
      'any.only': '"purpose" must be one of "one" or "all".',
      'any.required': '"purpose" is required.',
    }),
    orderId: Joi.number().integer().min(1).when('purpose', {
      is: 'one',
      then: Joi.required(),
      otherwise: Joi.forbidden(), // Prohibits orderId for 'all'
    }).messages({
      'number.base': '"orderId" must be a number.',
      'number.min': '"orderId" must be greater than or equal to 1.',
      'any.required': '"orderId" is required.',
    }),
    customerId: Joi.number().integer().min(1).required().messages({
      'number.base': '"customerId" must be a number.',
      'number.min': '"customerId" must be greater than or equal to 1.',
      'any.required': '"customerId" is required.',
    }),
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    if (purpose === 'one') {
      // Query for a single order
      const query = 'SELECT * FROM orders WHERE idorders = ? AND idcustomer = ?';
      const result = await queryDatabase(query, [orderId, customerId]);

      if (result.length === 0) {
        return res.status(404).json({ message: 'Order not found.' });
      }

      const orders = result[0];
      const parsedOrder = orders.order; // Parse the order data from JSON

      const orderData = {
        id: orders.idorders,
        customer: orders.idcustomer,
        order: parsedOrder, // Order data in JSON format
        order_time: orders.time
      };

      return res.status(200).json(orderData);
    } else if (purpose === 'all') {
      // Query for all orders
      const query = 'SELECT * FROM orders WHERE idcustomer = ?';
      const results = await queryDatabase(query, [customerId]);

      if (results.length === 0) {
        return res.status(404).json({ message: 'Orders not found.' });
      }

      const orderData = results.map(orders => {
        const parsedOrder = orders.order; // Parse the order data from JSON
        return {
          id: orders.idorders,
          customer: orders.idcustomer,
          order: parsedOrder, // Order data in JSON format
          order_time: orders.time
        };
      });

      return res.status(200).json(orderData);
    }
  } catch (err) {
    console.error('Error:', err);
    return res.status(500).json({ message: 'An error occurred. Please try again later.' });
  }
});

function queryDatabase(query, params) {
  return new Promise((resolve, reject) => {
    db.query(query, params, (err, results) => {
      if (err) {
        reject(err);
      } else {
        resolve(results);
      }
    });
  });
}

app.delete('/api/order/delete/oneAll', async (req, res) => { 
  const { customerId, orderId, purpose } = req.body;

  // Define Joi schema with conditional validation for the purpose and orderId
  const schema = Joi.object({
    purpose: Joi.string().valid('one', 'all').required().messages({
      'any.only': '"purpose" must be one of "one" or "all".',
      'any.required': '"purpose" is required.',
    }),
    orderId: Joi.number().integer().min(1).when('purpose', {
      is: 'one',
      then: Joi.required(), // Required when purpose is "one"
      otherwise: Joi.forbidden(), // Forbidden when purpose is "all"
    }).messages({
      'number.base': '"orderId" must be a number.',
      'number.min': '"orderId" must be greater than or equal to 1.',
      'any.required': '"orderId" is required.',
    }),
    customerId: Joi.number().integer().min(1).required().messages({
      'number.base': '"customerId" must be a number.',
      'number.min': '"customerId" must be greater than or equal to 1.',
      'any.required': '"customerId" is required.',
    }),
  });

  // Validate the request body using the defined Joi schema
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    if (purpose === 'one') {
      // Delete a specific order
      const query = 'DELETE FROM orders WHERE idorders = ? AND idcustomer = ?';
      const result = await queryDatabase(query, [orderId, customerId]);

      // Check if the order was found and deleted
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: 'Order not found or already deleted.' });
      }

      return res.status(200).json({ message: 'Order deleted successfully.' });
    } else if (purpose === 'all') {
      // Delete all orders for a specific customer
      const query = 'DELETE FROM orders WHERE idcustomer = ?';
      const result = await queryDatabase(query, [customerId]);

      // Check if any orders were deleted
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: 'No orders found or already deleted for this customer.' });
      }

      return res.status(200).json({ message: 'All orders deleted successfully.' });
    }
  } catch (err) {
    console.error('Error:', err);
    return res.status(500).json({ message: 'An error occurred. Please try again later.' });
  }
});

app.put('/api/order/update', async (req, res) => {
  const { idcustomer, idorder, newQuantity } = req.body;

  // Validate the request body for update operation
  const schema = Joi.object({
    idcustomer: Joi.number().integer().min(1).required().messages({
      'number.base': '"idcustomer" must be a number.',
      'number.min': '"idcustomer" must be greater than or equal to 1.',
      'any.required': '"idcustomer" is required.',
    }),
    idorder: Joi.number().integer().min(1).required().messages({
      'number.base': '"idorder" must be a number.',
      'number.min': '"idorder" must be greater than or equal to 1.',
      'any.required': '"idorder" is required.',
    }),
    newQuantity: Joi.number().integer().min(0).required().messages({
      'number.base': '"newQuantity" must be a number.',
      'number.min': '"newQuantity" must be greater than or equal to 0.',
      'any.required': '"newQuantity" is required.',
    }),
  });

  // Validate the input data using Joi schema
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    // Fetch the product details from the database
    const productResults = await new Promise((resolve, reject) => {
      db.query('SELECT * FROM products WHERE idproducts = ?', [idorder], (err, results) => {
        if (err) return reject(err);
        resolve(results);
      });
    });

    const product = productResults[0];

    // Check if enough stock is available for the requested quantity
    if (newQuantity > product.quantity) {
      return res.status(400).json({ message: 'Not enough quantity in stock.' });
    }

    // SQL query to fetch the customer's cart
    const query = 'SELECT `order` FROM orders WHERE idcustomer = ?';
    const [customerData] = await db.promise().query(query, [idcustomer]);

    if (customerData.length === 0) {
      return res.status(404).json({ message: 'Customer not found.' });
    }

    // Parse and process the cart data
    let cart = [];
    try {
      const rawOrderData = customerData[0].order;
      console.log('Raw order data:', rawOrderData);

      // If the raw data is not an array, convert it
      if (Array.isArray(rawOrderData)) {
        cart = rawOrderData;
      } else {
        cart = JSON.parse(rawOrderData);  // If JSON string, parse it
      }
      console.log('Parsed cart data:', cart);
    } catch (parseError) {
      console.error('Error parsing cart data:', parseError);
      return res.status(500).json({ message: 'Invalid cart data. Please contact support.' });
    }

    // Ensure cart is an array
    if (!Array.isArray(cart)) {
      return res.status(500).json({ message: 'Cart data is not an array.' });
    }

    // Find and update the specific order in the cart
    let orderFound = false;
    const updatedCart = cart.map(item => {
      if (item.productId === idorder) {
        orderFound = true;
        return { ...item, quantity: newQuantity };
      }
      return item;
    });

    // If the order is not found in the cart
    if (!orderFound) {
      return res.status(404).json({ message: 'Order not found in cart.' });
    }

    // Update the cart in the database
    const updateQuery = 'UPDATE orders SET `order` = ? WHERE idcustomer = ?';
    await db.promise().query(updateQuery, [JSON.stringify(updatedCart), idcustomer]);

    // Update the product stock by adjusting the quantity
    const updatedProductQuantity = product.quantity - (newQuantity - cart[0].quantity);
    console.log(updatedProductQuantity);

    await new Promise((resolve, reject) => {
      db.query(
        'UPDATE products SET quantity = ? WHERE idproducts = ?',
        [updatedProductQuantity, idorder],
        (err, results) => {
          if (err) return reject(err);
          resolve(results);
        }
      );
    });

    res.status(200).json({
      message: 'Order updated successfully.',
      cart: updatedCart, // Return the updated cart
    });

  } catch (err) {
    console.error('Error processing request:', err);
    res.status(500).json({ message: 'An error occurred. Please try again later.' });
  }
});

app.post('/api/order/complete', async (req, res) => {
  const { customerId, orderId } = req.body;

  // Joi schema validation for the completion request
  const schema = Joi.object({
    orderId: Joi.number().integer().min(1).required().messages({
      'number.base': '"orderId" must be a number.',
      'number.min': '"orderId" must be greater than or equal to 1.',
      'any.required': '"orderId" is required.',
    }),
    customerId: Joi.number().integer().min(1).required().messages({
      'number.base': '"customerId" must be a number.',
      'number.min': '"customerId" must be greater than or equal to 1.',
      'any.required': '"customerId" is required.',
    }),
  });

  // Validate the request body
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    // Retrieve the order from the database
    const selectQuery = 'SELECT * FROM orders WHERE idorders = ? AND idcustomer = ?';
    const [orderResult] = await db.promise().query(selectQuery, [orderId, customerId]);

    if (orderResult.length === 0) {
      return res.status(404).json({ message: 'Order not found.' });
    }

    const order = orderResult[0];
    const parsedOrder = order.order; // Parse the order from JSON

    // Insert the order into the completed orders table
    const insertQuery = `
      INSERT INTO orders_copmleted (idcustomer, order_details, order_time)
      VALUES (?, ?, ?);
    `;
    const insertResult = await db.promise().query(insertQuery, [customerId, parsedOrder, order.time]);

    if (insertResult[0].affectedRows === 0) {
      return res.status(500).json({ message: 'Failed to move order to completed orders.' });
    }

    // Delete the original order
    const deleteQuery = 'DELETE FROM orders WHERE idorders = ? AND idcustomer = ?';
    const deleteResult = await db.promise().query(deleteQuery, [orderId, customerId]);

    if (deleteResult[0].affectedRows === 0) {
      return res.status(404).json({ message: 'Order not found or already deleted.' });
    }

    // Respond with success
    return res.status(200).json({ message: 'Order completed successfully.' });
  } catch (err) {
    console.error('Error completing order:', err);
    return res.status(500).json({ message: 'An error occurred. Please try again later.' });
  }
});




// Mock PayPal Payment simulation function
const simulatePayPalPayment = (paymentData) => {
  return new Promise((resolve, reject) => {
    // Simulated response structure
    const simulatedResponse = {
      id: 'SIMULATED_PAYMENT_ID',
      state: 'approved',
      payer: {
        payment_method: 'paypal',
      },
      transactions: [
        {
          amount: {
            total: paymentData.total,
            currency: paymentData.currency,
          },
          description: paymentData.description,
        },
      ],
    };

    // Simulate successful payment if total amount is greater than 0
    if (paymentData.total > 0) {
      resolve(simulatedResponse);
    } else {
      reject(new Error('Simulated payment error')); // Simulate payment failure for invalid amounts
    }
  });
};

// Function to save the payment receipt to the database
const savePaymentReceipt = async (payment, idcustomer, order_id) => {
  try {
    // Create a receipt object
    const receipt = {
      order_id: order_id,
      customer_id: idcustomer,
      payment_id: payment.id,
      payment_status: payment.state,
      payment_method: payment.payer.payment_method,
      total_amount: payment.transactions[0].amount.total,
      currency: payment.transactions[0].amount.currency,
      description: payment.transactions[0].description,
      payment_date: new Date(),
    };

    // SQL query to insert payment receipt into the database
    const query = `
      INSERT INTO payments (
        orderid, customerid, idpayments, paymentstatus, 
        paymentmethod, totalamount, currency, description, paymentdate
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const values = [
      receipt.order_id,
      receipt.customer_id,
      receipt.payment_id,
      receipt.payment_status,
      receipt.payment_method,
      receipt.total_amount,
      receipt.currency,
      receipt.description,
      receipt.payment_date,
    ];

    // Execute the query and return the saved receipt
    const [result] = await db.promise().query(query, values);
    console.log('Payment receipt saved successfully:', result.insertId);
    return { id: result.insertId, ...receipt };
  } catch (error) {
    console.error('Error saving payment receipt:', error);
    throw error; // Throw error if saving the receipt fails
  }
};

// Function to fetch the most recent order by customer ID
const getOrderById = async (req, res) => {
  const { idcustomer } = req.body;

  // Validate the request body
  const schema = Joi.object({
    idcustomer: Joi.number().integer().min(1).required().messages({
      'number.base': '"idcustomer" must be a number.',
      'number.min': '"idcustomer" must be greater than or equal to 1.',
      'any.required': '"idcustomer" is required.',
    }),
    currency: Joi.string().length(3).optional(),
    description: Joi.string().min(8).optional(),
    promotionCode: Joi.string().min(8).optional(),
  });

  // Validate the request body against the schema
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    // SQL query to fetch the most recent order for the customer
    const query = `
      SELECT * FROM orders
      WHERE idcustomer = ?
      ORDER BY time DESC
      LIMIT 1;
    `;

    // Execute the query
    const [results] = await db.promise().query(query, [idcustomer]);

    if (results.length === 0) {
      return res.status(404).json({ message: 'No orders found for this customer.' });
    }

    // Return the most recent order's ID
    const latestOrderId = results[0].idorders;
    console.log(latestOrderId);
    return latestOrderId;
  } catch (err) {
    console.error('Error fetching order:', err); // Log any errors encountered
  }
};

// Function to prepare the payment receipt data
const preparePaymentReceipt = async (idcustomer) => {
  // Fetch the customer's cart data
  const query = 'SELECT cart FROM users WHERE id = ?';
  const [customerData] = await db.promise().query(query, [idcustomer]);

  if (customerData.length === 0) {
    throw new Error('Customer not found.'); // Handle case when customer doesn't exist
  }

  let cart = [];
  try {
    // Parse the cart data
    cart = customerData[0].cart;
    console.log(cart);
  } catch (parseError) {
    console.warn('Invalid JSON in cart data:', parseError); // Handle invalid JSON
    throw new Error('Invalid cart data.');
  }

  if (cart.length === 0) {
    throw new Error('Cart is empty.'); // Handle empty cart
  }

  let totalAmount = 0;

  // Calculate the total amount by iterating over the cart items
  for (const item of cart) {
    const productId = item.productId;
    const quantity = item.quantity;
    const [productResults] = await db.promise().query(
      'SELECT * FROM products WHERE idproducts = ?',
      [productId]
    );

    if (productResults.length === 0) {
      throw new Error(`Product with ID ${productId} not found.`); // Handle case when product doesn't exist
    }

    const product = productResults[0];

    const productCategory = product.category;

    totalAmount += product.price * quantity; // Update total amount based on product price and quantity
    try {
      // Check for campaigns affecting total amount based on product category
      const result = await processCampaignDetect(productCategory, totalAmount);
      if (result.success === true) {
        console.log(result);
        totalAmount = result.finalAmount;
        console.log(totalAmount);
      }
    } catch (error) {
      console.error(error); // Handle any errors in campaign processing
    }
  }

  return totalAmount; // Return the final total amount after processing campaigns
};

// Payment route handler
app.post('/api/pay', async (req, res) => {
  const { idcustomer, currency, description, promotionCode } = req.body;

  // Validate the incoming request data
  const schema = Joi.object({
    idcustomer: Joi.number().integer().min(1).required().messages({
      'any.required': '"idcustomer" is required.',
      'number.base': '"idcustomer" must be a number.',
      'number.min': '"idcustomer" must be greater than or equal to 1.',
    }),
    currency: Joi.string().length(3).required().messages({
      'any.required': '"currency" is required.',
      'string.base': '"currency" must be a string.',
      'string.length': '"currency" must be exactly 3 characters long.',
    }),
    description: Joi.string().min(8).required().messages({
      'any.required': '"description" is required.',
      'string.base': '"description" must be a string.',
      'string.min': '"description" must be at least 8 characters long.',
    }),
    promotionCode: Joi.string().min(1).optional().messages({
      'string.base': '"promotionCode" must be a string.',
      'string.min': '"promotionCode" must be at least 1 character long.',
    }),
  });

  // Validate request body
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    // Calculate the total amount for the payment
    const totalAmount = await preparePaymentReceipt(idcustomer);
    let total;
    if (promotionCode) {
      // Apply promotion code if provided
      const result = await processPromotionCodeDetect(promotionCode, totalAmount);
      total = result.finalAmount;
      console.log(result);
      console.log(total);
    } else {
      total = totalAmount; // Use the total amount without promotion code
    }
    const paymentData = { total, currency, description };
    // Simulate PayPal payment
    const payment = await simulatePayPalPayment(paymentData);
    // Process the cart into an order
    await processCartToOrder(db, req, res);
    // Fetch the order ID
    const order_id = await getOrderById(req, res);
    // Save the payment receipt to the database
    receipt = await savePaymentReceipt(payment, idcustomer, order_id);
    res.status(200).json({ message: 'Payment successful', receipt: receipt }); // Return success response
  } catch (err) {
    try {
      // Handle payment failure and return error message
      res.status(500).json({ message: 'Payment failed', error: err.message });
    } catch (error) {
      // Handle unexpected errors
    }
  }
});



// Define a GET route to retrieve receipts for a specific customer
app.get('/api/receipt/get/:idcustomer', async (req, res) => {
  const { idcustomer } = req.params;

  // Validation schema for the incoming request data
  const schema = Joi.object({
    idcustomer: Joi.number().integer().min(1).required().messages({
      'number.base': '"idcustomer" must be a number.',
      'number.min': '"idcustomer" must be greater than or equal to 1.',
      'any.required': '"idcustomer" is required.',
    }),
  });

  // Validate the request body against the schema
  const { error } = schema.validate({ idcustomer });
  if (error) {
    // If validation fails, return a 400 status with the error message
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    // SQL query to fetch all receipts for the specified customer
    const query = `
      SELECT * FROM payments
      WHERE customerid = ?;
    `;

    // Execute the query
    const [results] = await db.promise().query(query, [idcustomer]);

    // If no receipts are found, return a 404 status
    if (results.length === 0) {
      return res.status(404).json({ message: 'No receipts found for this customer.' });
    }

    // If receipts are found, return them in JSON format with a 200 status
    return res.status(200).json({ receipts: results });
  } catch (err) {
    // If an error occurs while fetching the data, return a 500 status
    console.error('Error fetching receipts:', err);
    return res.status(500).json({ message: 'Internal server error.' });
  }
});




// Route to add a return demand
app.post('/api/return/demand/add', async (req, res) => { 
  const { customerId, orderId, reason, description } = req.body;

  // Validate input with Joi
  const schema = Joi.object({
    customerId: Joi.number().integer().min(1).required().messages({
      'number.base': '"customerId" must be a number.',
      'number.min': '"customerId" must be greater than or equal to 1.',
      'any.required': '"customerId" is required.',
    }),
    orderId: Joi.number().integer().min(1).required().messages({
      'number.base': '"orderId" must be a number.',
      'number.min': '"orderId" must be greater than or equal to 1.',
      'any.required': '"orderId" is required.',
    }),
    reason: Joi.string().max(255).required().messages({
      'string.base': '"reason" must be a string.',
      'string.max': '"reason" must not exceed 255 characters.',
      'any.required': '"reason" is required.',
    }),
    description: Joi.string().max(500).optional().allow(null, '').messages({
      'string.base': '"description" must be a string.',
      'string.max': '"description" must not exceed 500 characters.',
    }),
  });

  // Validate request body with the schema
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    // 1. Check if the order belongs to the customer
    const orderCheckQuery = 'SELECT * FROM orders WHERE idorders = ? AND idcustomer = ?';
    const [orderResult] = await db.promise().query(orderCheckQuery, [orderId, customerId]);

    if (orderResult.length === 0) {
      return res.status(404).json({ message: 'Order not found for this customer.' });
    }

    // 2. Save the return request
    const insertQuery = 
      'INSERT INTO return_requests (idcustomer, idorder, reason, description, request_date, status) ' +
      'VALUES (?, ?, ?, ?, NOW(), "pending")';
    const [insertResult] = await db.promise().query(insertQuery, [customerId, orderId, reason, description]);

    if (insertResult.affectedRows === 0) {
      return res.status(500).json({ message: 'Failed to create return request.' });
    }

    // 3. Successful response
    return res.status(200).json({ message: 'Return request created successfully.' });
  } catch (err) {
    console.error('Error creating return request:', err);
    return res.status(500).json({ message: 'An error occurred. Please try again later.' });
  }
});

// Route to retrieve one or all return demands
app.get('/api/return/demand/get/oneAll/:customerId/:orderId/:purpose/:status', async (req, res) => {
  const { customerId, orderId, purpose, status } = req.params;

  // Validate input with Joi
  const schema = Joi.object({
    customerId: Joi.number().integer().min(1).required().messages({
      'number.base': '"customerId" must be a number.',
      'number.min': '"customerId" must be greater than or equal to 1.',
      'any.required': '"customerId" is required.',
    }),
    orderId: Joi.number().integer().min(1).when('purpose', {
      is: 'one',
      then: Joi.required(),
      otherwise: Joi.forbidden(), // 'all' forbids orderId
    }).messages({
      'number.base': '"orderId" must be a number.',
      'number.min': '"orderId" must be greater than or equal to 1.',
      'any.required': '"orderId" is required.',
    }),
    purpose: Joi.string().valid('one', 'all').required().messages({
      'any.only': '"purpose" must be either "one" or "all".',
      'any.required': '"purpose" is required.',
    }),
    status: Joi.string().valid('pending', 'approved', 'rejected').optional().messages({
      'any.only': '"status" must be one of "pending", "approved", or "rejected".',
    }),
  });

  // Validate request body with the schema
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    if (purpose === 'one') {
      // 1. Check if the order belongs to the customer
      const orderCheckQuery = 'SELECT * FROM return_requests WHERE idcustomer = ? AND idorder = ?';
      const [orderResult] = await db.promise().query(orderCheckQuery, [customerId, orderId]);

      if (orderResult.length === 0) {
        return res.status(404).json({ message: 'No return request found for this order and customer.' });
      }

      // 2. Return the return request
      return res.status(200).json({
        message: 'Return request retrieved successfully.',
        data: orderResult,
      });
    } else if (purpose === 'all') {
      // 3. Get all return requests (filter by status if provided)
      let allRequestsQuery = 'SELECT * FROM return_requests WHERE idcustomer = ?';
      const queryParams = [customerId];

      if (status) {
        allRequestsQuery += ' AND status = ?';
        queryParams.push(status);
      }

      const [allRequestsResult] = await db.promise().query(allRequestsQuery, queryParams);

      if (allRequestsResult.length === 0) {
        return res.status(404).json({ message: 'No return requests found for this customer.' });
      }

      // 4. Return all return requests
      return res.status(200).json({
        message: 'All return requests retrieved successfully.',
        data: allRequestsResult,
      });
    }
  } catch (err) {
    console.error('Error fetching return request:', err);
    return res.status(500).json({ message: 'An error occurred while fetching the return request.' });
  }
});

// Route to update return demand status
app.put('/api/return/demand/status/set', async (req, res) => {
  const { customerId, orderId, status } = req.body;

  // Validate input with Joi
  const schema = Joi.object({
    customerId: Joi.number().integer().min(1).required().messages({
      'number.base': '"customerId" must be a number.',
      'number.min': '"customerId" must be greater than or equal to 1.',
      'any.required': '"customerId" is required.',
    }),
    orderId: Joi.number().integer().min(1).required().messages({
      'number.base': '"orderId" must be a number.',
      'number.min': '"orderId" must be greater than or equal to 1.',
      'any.required': '"orderId" is required.',
    }),
    status: Joi.string().valid('pending', 'approved', 'rejected').required().messages({
      'any.only': '"status" must be one of "pending", "approved", or "rejected".',
      'any.required': '"status" is required.',
    }),
  });

  // Validate request body with the schema
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    // 1. Check if the order belongs to the customer
    const orderCheckQuery = 'SELECT * FROM return_requests WHERE idcustomer = ? AND idorder = ?';
    const [orderResult] = await db.promise().query(orderCheckQuery, [customerId, orderId]);

    if (orderResult.length === 0) {
      return res.status(404).json({ message: 'No return request found for this order and customer.' });
    }

    // 2. Update the return request status
    const updateQuery = 'UPDATE return_requests SET status = ? WHERE idcustomer = ? AND idorder = ?';
    const [updateResult] = await db.promise().query(updateQuery, [status, customerId, orderId]);

    if (updateResult.affectedRows === 0) {
      return res.status(500).json({ message: 'Failed to update return request status.' });
    }

    // 3. Successful response
    return res.status(200).json({ message: 'Return request status updated successfully.' });
  } catch (err) {
    console.error('Error updating return request status:', err);
    return res.status(500).json({ message: 'An error occurred while updating the return request status.' });
  }
});

app.post('/api/return/complete', async (req, res) => { 
  // Destructure the request body to get the required data
  const { customerId, orderId, amount, currency, description, paymentMethod } = req.body;

  // Joi validation schema for input data
  const schema = Joi.object({
    customerId: Joi.number().integer().min(1).required().messages({
      'number.base': '"customerId" must be a number.',
      'number.min': '"customerId" must be greater than or equal to 1.',
      'any.required': '"customerId" is required.',
    }),
    orderId: Joi.number().integer().min(1).required().messages({
      'number.base': '"orderId" must be a number.',
      'number.min': '"orderId" must be greater than or equal to 1.',
      'any.required': '"orderId" is required.',
    }),
    amount: Joi.number().positive().required().messages({
      'number.base': '"amount" must be a number.',
      'number.positive': '"amount" must be greater than 0.',
      'any.required': '"amount" is required.',
    }),
    currency: Joi.string().required().messages({
      'any.required': '"currency" is required.',
    }),
    description: Joi.string().required().messages({
      'any.required': '"description" is required.',
    }),
    paymentMethod: Joi.string().valid('paypal', 'credit_card').required().messages({
      'any.only': '"paymentMethod" must be either "paypal" or "credit_card".',
      'any.required': '"paymentMethod" is required.',
    }),
  });

  // Validate the input data against the schema
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    // 1. Check if the return request exists and is approved
    const orderCheckQuery = 'SELECT * FROM return_requests WHERE idcustomer = ? AND idorder = ? AND status = "approved"';
    const [orderResult] = await db.promise().query(orderCheckQuery, [customerId, orderId]);

    if (orderResult.length === 0) {
      return res.status(404).json({ message: 'No pending return request found for this order and customer.' });
    }

    // 2. Mark the return request as completed by updating the status
    const updateQuery = 'UPDATE return_requests SET status = "completed", completion_date = NOW() WHERE idcustomer = ? AND idorder = ?';
    const [updateResult] = await db.promise().query(updateQuery, [customerId, orderId]);

    if (updateResult.affectedRows === 0) {
      return res.status(500).json({ message: 'An error occurred while completing the return request.' });
    }
    processReturnPayment(amount, currency, description, paymentMethod);
    // 3. Notify success upon completion
    return res.status(200).json({
      message: 'Return request completed successfully.',
      data: {
        customerId,
        orderId,
        status: 'completed',
      },
    });

  } catch (err) {
    // Error handling for the try block
    console.error('Error completing return request:', err);
    return res.status(500).json({ message: 'An error occurred while completing the return request.' });
  }
});

// Function to process the return payment
const processReturnPayment = async (amount, currency, description, paymentMethod) => {
  const returnData = {
    amount: amount,
    currency: currency,
    description: description,
    paymentMethod: paymentMethod,
  };

  try {
    // Simulate the payment process
    const paymentResult = await simulateReturnPayment(returnData);
    console.log('Refund processed successfully:', paymentResult);
  } catch (err) {
    // Handle errors during payment simulation
    console.error('Error processing refund:', err.message);
  }
};

// Function to simulate the return payment
const simulateReturnPayment = (returnData) => {
  return new Promise((resolve, reject) => {
    // Simulated payment response
    const simulatedResponse = {
      transactionId: 'SIMULATED_RETURN_PAYMENT_ID',
      state: 'completed', // Simulating 'completed' or 'failed' status
      payer: {
        method: returnData.paymentMethod || 'unknown',
      },
      refund: {
        total: returnData.amount,
        currency: returnData.currency,
        description: returnData.description,
      },
      completedAt: new Date().toISOString(), // Payment completion time
    };

    if (returnData.amount > 0) {
      // Successful payment if amount is positive
      resolve(simulatedResponse);
    } else if (returnData.amount === 0) {
      // Special error for zero refund amount
      reject(new Error('Refund amount cannot be zero.'));
    } else {
      // Error for invalid negative refund amount
      reject(new Error('Invalid refund amount.'));
    }
  });
};




// Add or update a comment for a product
app.post('/api/comment/addAndUptade', async (req, res) => { 
  const { idcustomer, idproduct, text } = req.body;

  // Validate the request body
  const schema = Joi.object({
    idcustomer: Joi.number().integer().min(1).required().messages({
      'number.base': '"idcustomer" must be a number.',
      'number.min': '"idcustomer" must be greater than or equal to 1.',
      'any.required': '"idcustomer" is required.',
    }),
    idproduct: Joi.number().integer().min(1).required().messages({
      'number.base': '"idproduct" must be a number.',
      'number.min': '"idproduct" must be greater than or equal to 1.',
      'any.required': '"idproduct" is required.',
    }),
    text: Joi.string().max(255).required().messages({
      'string.base': '"text" must be a string.',
      'string.max': '"text" must not exceed 255 characters.',
      'any.required': '"text" is required.',
    }),
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    // Check if the product exists
    const [productResults] = await db.promise().query('SELECT * FROM products WHERE idproducts = ?', [idproduct]);

    if (productResults.length === 0) {
      return res.status(404).json({ message: 'Product not found.' });
    }

    // Retrieve and parse comments
    const [customerData] = await db.promise().query('SELECT comments FROM products WHERE idproducts = ?', [idproduct]);

    if (customerData.length === 0) {
      return res.status(404).json({ message: 'Comments not found.' });
    }

    let comments = [];
    try {
      comments = customerData[0].comments || [];
      console.log(comments);
    } catch (parseError) {
      console.error('Error parsing comments JSON:', parseError);
      return res.status(500).json({ message: 'Invalid comments data. Please contact support.' });
    }

    // Update or add comment
    const existingComment = comments.find(comment => comment.costumerId === idcustomer);
    if (existingComment) {
      existingComment.comment = text;
    } else {
      comments.push({ productId: idproduct, comment: text, costumerId: idcustomer });
    }
    
    // Update the database
    await db.promise().query('UPDATE products SET comments = ? WHERE idproducts = ?', [JSON.stringify(comments), idproduct]);

    res.status(200).json({
      message: 'Comment updated successfully.',
      comments,
    });
  } catch (err) {
    console.error('Error processing request:', err);
    res.status(500).json({ message: 'An error occurred while processing the request. Please try again later.' });
  }
});

// Retrieve comments for a product based on purpose (one or all)
app.get('/api/comment/get/oneAll/:idcustomer/:idproduct/:purpose', async (req, res) => {
  const { idcustomer, idproduct, purpose } = req.params;

  // Validate the request body
  const schema = Joi.object({
    purpose: Joi.string().valid('one', 'all').required().messages({
      'any.only': '"purpose" must be one of "one" or "all".',
      'any.required': '"purpose" is required.',
    }),
    idcustomer: Joi.number().integer().min(1).when('purpose', {
      is: 'one',
      then: Joi.required(),
      otherwise: Joi.forbidden(), // For 'all', disallow idcustomer
    }).messages({
      'number.base': '"idcustomer" must be a number.',
      'number.min': '"idcustomer" must be greater than or equal to 1.',
      'any.required': '"idcustomer" is required.',
    }),
    idproduct: Joi.number().integer().min(1).required().messages({
      'number.base': '"idproduct" must be a number.',
      'number.min': '"idproduct" must be greater than or equal to 1.',
      'any.required': '"idproduct" is required.',
    }),
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    // Retrieve comments for the specified product
    const [productData] = await db.promise().query('SELECT comments FROM products WHERE idproducts = ?', [idproduct]);

    if (productData.length === 0) {
      return res.status(404).json({ message: 'Product not found.' });
    }

    let comments = [];
    try {
      comments = productData[0].comments || []; // Ensure comments are parsed correctly
    } catch (parseError) {
      console.error('Error parsing comments JSON:', parseError);
      return res.status(500).json({ message: 'Invalid comments data. Please contact support.' });
    }

    if (purpose === 'all') {
      res.status(200).json({
        message: 'Comments retrieved successfully.',
        comments,
      });
    } else if (purpose === 'one') {
      const existingComment = comments.find(comment => comment.costumerId === idcustomer);
      if (existingComment) {
        res.status(200).json({
          message: 'Comment retrieved successfully.',
          existingComment,
        });
      } else {
        res.status(404).json({ message: 'Comment not found for this customer.' });
      }
    }
  } catch (err) {
    console.error('Error processing request:', err);
    res.status(500).json({ message: 'An error occurred while processing the request. Please try again later.' });
  }
});

// Delete comments for a product based on purpose (one or all)
app.delete('/api/comment/delete/oneAll', async (req, res) => {
  const { idcustomer, idproduct, purpose } = req.body;

  // Validate the request body
  const schema = Joi.object({
    purpose: Joi.string().valid('one', 'all').required().messages({
      'any.only': '"purpose" must be one of "one" or "all".',
      'any.required': '"purpose" is required.',
    }),
    idcustomer: Joi.number().integer().min(1).when('purpose', {
      is: 'one',
      then: Joi.required(),
      otherwise: Joi.forbidden(), // For 'all', disallow idcustomer
    }).messages({
      'number.base': '"idcustomer" must be a number.',
      'number.min': '"idcustomer" must be greater than or equal to 1.',
      'any.required': '"idcustomer" is required.',
    }),
    idproduct: Joi.number().integer().min(1).required().messages({
      'number.base': '"idproduct" must be a number.',
      'number.min': '"idproduct" must be greater than or equal to 1.',
      'any.required': '"idproduct" is required.',
    }),
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {

    if (purpose === 'all') {
      const queryssel = 'SELECT comments FROM products WHERE idproducts = ?';
      const [productData] = await db.promise().query(queryssel, [idproduct]);

      if (productData.length === 0) {
        return res.status(404).json({ message: 'Product not found.' });
      }
      // SQL query to clear all comments for the specified product
      const query = 'UPDATE products SET comments = ? WHERE idproducts = ?';
      const result = await db.promise().query(query, [JSON.stringify([]), idproduct]);

      if (result.affectedRows === 0) {
        return res.status(404).json({ message: 'Product not found.' });
      }

      return res.status(200).json({
        message: 'All comments cleared successfully.',
      });
    } else if (purpose === 'one') {
      // SQL query to fetch the product's comments
      const query = 'SELECT comments FROM products WHERE idproducts = ?';
      const [productData] = await db.promise().query(query, [idproduct]);

      if (productData.length === 0) {
        return res.status(404).json({ message: 'Product not found.' });
      }

      // Parse the comments
      let comments = [];
      try {
        comments = productData[0].comments || [];
        console.log(comments)
      } catch (parseError) {
        console.error('Error parsing comments JSON:', parseError);
        return res.status(500).json({ message: 'Invalid comments data. Please contact support.' });
      }

      // Find and remove the comment of the specific customer
      const updatedComments = comments.filter(comment => comment.costumerId !== idcustomer);

      // If no comment was removed, return an error
      if (updatedComments.length === comments.length) {
        return res.status(404).json({ message: 'Comment not found for the specified customer.' });
      }

      // Update the product with the new comments list
      const updateQuery = 'UPDATE products SET comments = ? WHERE idproducts = ?';
      await db.promise().query(updateQuery, [JSON.stringify(updatedComments), idproduct]);

      return res.status(200).json({
        message: 'Comment removed successfully.',
        comments: updatedComments, // Return the updated comments
      });
    }
  } catch (err) {
    console.error('Error processing request:', err);
    res.status(500).json({ message: 'An error occurred while processing the request. Please try again later.' });
  }
});




// Endpoint to add or update a promotion code
app.post('/api/promotionCode/addAndUpdate', async (req, res) => { 
  const { promotionCode, stateDate, endDate, usageLimit, status, promotionType, promotionAmount } = req.body;

  // Validate the request body using Joi schema
  const schema = Joi.object({
    promotionCode: Joi.string().min(1).required().messages({
      'any.required': '"promotionCode" is required.',
      'string.min': '"promotionCode" must be at least 1 character long.',
    }),
    stateDate: Joi.date().required().messages({
      'any.required': '"stateDate" is required.',
      'date.base': '"stateDate" must be a valid date.',
    }),
    endDate: Joi.date().required().messages({
      'any.required': '"endDate" is required.',
      'date.base': '"endDate" must be a valid date.',
    }),
    usageLimit: Joi.number().integer().min(1).allow(null).messages({
      'number.base': '"usageLimit" must be a number.',
      'number.min': '"usageLimit" must be at least 1.',
    }),
    status: Joi.string().valid('active', 'inactive').required().messages({
      'any.required': '"status" is required.',
      'any.only': '"status" must be one of "active" or "inactive".',
    }),
    promotionType: Joi.string().valid('fixed', 'percentage').allow(null).messages({
      'string.base': '"promotionType" must be a string.',
    }),
    promotionAmount: Joi.number().required().messages({
      'number.base': '"promotionAmount" must be a number.',
    }),
  });

  // Check if the request body is valid
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    // Check if the promotion code already exists in the database
    const [existingPromotion] = await db
      .promise()
      .query('SELECT * FROM promotion_codes WHERE promotion_code = ?', [promotionCode]);

    if (existingPromotion.length > 0) {
      // Update existing promotion if found
      const updateQuery = `
        UPDATE promotion_codes 
        SET 
          state_date = ?, 
          end_date = ?, 
          usage_limit = ?, 
          status = ?, 
          promotion_type = ?, 
          promotion_amount = ? 
        WHERE promotion_code = ?
      `;
      await db
        .promise()
        .query(updateQuery, [stateDate, endDate, usageLimit, status, promotionType, promotionAmount, promotionCode]);

      // Send success response for update
      res.status(200).json({
        message: 'Promotion code updated successfully.',
        promotionCode,
      });
    } else {
      // Insert new promotion if not found
      const insertQuery = `
        INSERT INTO promotion_codes (promotion_code, state_date, end_date, usage_limit, status, promotion_type, promotion_amount) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `;
      await db
        .promise()
        .query(insertQuery, [promotionCode, stateDate, endDate, usageLimit, status, promotionType, promotionAmount]);

      // Send success response for insert
      res.status(201).json({
        message: 'Promotion code added successfully.',
        promotionCode,
      });
    }
  } catch (err) {
    // Handle errors during database operations
    console.error('Error processing request:', err);
    res.status(500).json({ message: 'An error occurred while processing the request. Please try again later.' });
  }
});

// Endpoint to retrieve promotion codes (one or all based on purpose)
app.get('/api/promotionCode/get/oneAll/:promotionCode/:purpose', async (req, res) => {
  const { promotionCode, purpose } = req.params;

  // Validate the request body
  const schema = Joi.object({
    purpose: Joi.string().valid('one', 'all').required().messages({
      'any.only': '"purpose" must be one of "one" or "all".',
      'any.required': '"purpose" is required.',
    }),
    promotionCode: Joi.string().min(1).when('purpose', {
      is: 'one',
      then: Joi.required(),
      otherwise: Joi.forbidden(), // 'all' doesn't require promotionCode
    }).messages({
      'string.base': '"promotionCode" must be a string.',
      'string.min': '"promotionCode" must be at least 1 character long.',
      'any.required': '"promotionCode" is required for purpose "one".',
      'any.forbidden': '"promotionCode" is not allowed for purpose "all".',
    }),
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    if (purpose === 'all') {
      // Retrieve all promotion codes
      const [results] = await db.promise().query('SELECT * FROM promotion_codes');
      return res.status(200).json({
        message: 'All promotion codes retrieved successfully.',
        promotionCodes: results,
      });
    } else if (purpose === 'one') {
      // Retrieve a specific promotion code by code
      const [result] = await db
        .promise()
        .query('SELECT * FROM promotion_codes WHERE promotion_code = ?', [promotionCode]);

      if (result.length > 0) {
        return res.status(200).json({
          message: 'Promotion code retrieved successfully.',
          promotionCode: result[0],
        });
      } else {
        return res.status(404).json({
          message: 'Promotion code not found.',
        });
      }
    }
  } catch (err) {
    // Handle any errors during the request
    console.error('Error processing request:', err);
    return res.status(500).json({ message: 'An error occurred while processing the request. Please try again later.' });
  }
});

// Endpoint to delete promotion codes (one or all based on purpose)
app.delete('/api/promotionCode/delete/oneAll', async (req, res) => {
  const { promotionCode, purpose } = req.body;

  // Validate the request body
  const schema = Joi.object({
    purpose: Joi.string().valid('one', 'all').required().messages({
      'any.only': '"purpose" must be one of "one" or "all".',
      'any.required': '"purpose" is required.',
    }),
    promotionCode: Joi.string().min(1).when('purpose', {
      is: 'one',
      then: Joi.required(),
      otherwise: Joi.forbidden(), // 'all' doesn't require promotionCode
    }).messages({
      'string.base': '"promotionCode" must be a string.',
      'string.min': '"promotionCode" must be at least 1 character long.',
      'any.required': '"promotionCode" is required for purpose "one".',
      'any.forbidden': '"promotionCode" is not allowed for purpose "all".',
    }),
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    if (purpose === 'all') {
      // Delete all promotion codes
      const [results] = await db.promise().query('DELETE FROM promotion_codes');
      return res.status(200).json({
        message: 'All promotion codes deleted successfully.',
        affectedRows: results.affectedRows,
      });
    } else if (purpose === 'one') {
      // Delete a specific promotion code by code
      const [result] = await db
        .promise()
        .query('DELETE FROM promotion_codes WHERE promotion_code = ?', [promotionCode]);

      if (result.affectedRows > 0) {
        return res.status(200).json({
          message: 'Promotion code deleted successfully.',
          deletedPromotionCode: promotionCode,
        });
      } else {
        return res.status(404).json({
          message: 'Promotion code not found.',
        });
      }
    }
  } catch (err) {
    // Handle any errors during the request
    console.error('Error processing request:', err);
    return res.status(500).json({ message: 'An error occurred while processing the request. Please try again later.' });
  }
});

// Function to process the promotion code and calculate discount
const processPromotionCodeDetect = async (promotionCode, totalAmount) => {
  try {
    // Validation for promotion code and total amount
    if (!promotionCode || typeof promotionCode !== 'string' || promotionCode.trim() === '') {
      throw new Error('Promotion code is invalid or missing.');
    }
    if (typeof totalAmount !== 'number' || totalAmount <= 0) {
      throw new Error('Total amount must be a positive number.');
    }

    // Check if the promotion code exists in the database
    const [promotionCodeData] = await db
      .promise()
      .query('SELECT * FROM promotion_codes WHERE promotion_code = ?', [promotionCode]);

    if (promotionCodeData.length === 0) {
      return {
        success: false,
        message: 'Invalid promotion code.',
      };
    }

    const promotion = promotionCodeData[0];

    // Check the validity of the promotion code dates
    const currentDate = new Date();
    const startDate = new Date(promotion.start_date);
    const endDate = new Date(promotion.end_date);

    if (currentDate < startDate || currentDate > endDate) {
      return {
        success: false,
        message: 'Promotion code is expired or not yet active.',
      };
    }

    if (promotion.status === 'inactive') {
      return {
        success: false,
        message: 'Promotion code is inactive.',
      };
    }

    if (promotion.usage_limit && promotion.usage_count === 0) {
      return {
        success: false,
        message: 'Promotion code has reached its usage limit.',
      };
    }

    // Calculate discount based on promotion type (percentage or fixed)
    let discountAmount = 0;
    if (promotion.promotion_type === 'percentage') {
      discountAmount = (totalAmount * promotion.promotion_amount) / 100;
    } else if (promotion.promotion_type === 'fixed') {
      discountAmount = promotion.promotion_amount;
    }

    // Apply discount and calculate final amount
    const finalAmount = totalAmount - discountAmount;

    // Return success response with final discount and amount
    return {
      success: true,
      message: 'Promotion code applied successfully.',
      originalAmount: totalAmount,
      discountAmount,
      finalAmount,
    };
  } catch (err) {
    // Handle any errors during promotion code processing
    console.error('Error processing promotion code:', err.message);
    return {
      success: false,
      message: 'An error occurred while processing the promotion code. Please try again later.',
    };
  }
};




// Route to add or update a campaign
app.post('/api/campaign/addAndUpdate', async (req, res) => { 
  // Destructure fields from the request body
  const {
    campaignName,
    startDate,
    endDate,
    usageLimit,
    status,
    validCategories,
    campaignType,
    campaignAmount,
  } = req.body;

  // Validate the request body using Joi schema
  const schema = Joi.object({
    campaignName: Joi.string().min(1).required().messages({
      'any.required': '"campaignName" is required.',
      'string.min': '"campaignName" must be at least 1 character long.',
    }),
    startDate: Joi.date().required().messages({
      'any.required': '"startDate" is required.',
      'date.base': '"startDate" must be a valid date.',
    }),
    endDate: Joi.date().required().messages({
      'any.required': '"endDate" is required.',
      'date.base': '"endDate" must be a valid date.',
    }),
    usageLimit: Joi.number().integer().min(1).allow(null).messages({
      'number.base': '"usageLimit" must be a number.',
      'number.min': '"usageLimit" must be at least 1.',
    }),
    status: Joi.string().valid('active', 'inactive').required().messages({
      'any.required': '"status" is required.',
      'any.only': '"status" must be one of "active" or "inactive".',
    }),
    validCategories: Joi.string().allow(null).messages({
      'string.base': '"validCategories" must be a string.',
    }),
    campaignType: Joi.string().valid('fixed', 'percentage').required().messages({
      'any.required': '"campaignType" is required.',
      'any.only': '"campaignType" must be one of "fixed" or "percentage".',
    }),
    campaignAmount: Joi.number().required().messages({
      'number.base': '"campaignAmount" must be a number.',
    }),
  });

  // Validate the incoming data
  const { error } = schema.validate(req.body);
  if (error) {
    // If validation fails, return an error response with the validation message
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    // Check if the campaign already exists in the database by its name
    const [existingCampaign] = await db
      .promise()
      .query('SELECT * FROM campaigns WHERE campaign_name = ?', [campaignName]);

    if (existingCampaign.length > 0) {
      // If campaign exists, update it with new values
      const updateQuery = `
        UPDATE campaigns 
        SET 
          start_date = ?, 
          end_date = ?, 
          usage_limit = ?, 
          status = ?, 
          valid_categories = ?, 
          campaign_type = ?, 
          campaign_amount = ? 
        WHERE campaign_name = ?
      `;
      await db
        .promise()
        .query(updateQuery, [startDate, endDate, usageLimit, status, validCategories, campaignType, campaignAmount, campaignName]);

      // Return success response
      res.status(200).json({
        message: 'Campaign updated successfully.',
        campaignName,
      });
    } else {
      // If campaign does not exist, insert a new record
      const insertQuery = `
        INSERT INTO campaigns (campaign_name, start_date, end_date, usage_limit, status, valid_categories, campaign_type, campaign_amount) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `;
      await db
        .promise()
        .query(insertQuery, [campaignName, startDate, endDate, usageLimit, status, validCategories, campaignType, campaignAmount]);

      // Return success response for insertion
      res.status(201).json({
        message: 'Campaign added successfully.',
        campaignName,
      });
    }
  } catch (err) {
    // Log error and return internal server error message
    console.error('Error processing request:', err);
    res.status(500).json({ message: 'An error occurred while processing the request. Please try again later.' });
  }
});

// Route to delete campaigns (one or all)
app.delete('/api/campaign/delete/oneAll', async (req, res) => {
  // Destructure fields from the request body
  const { campaignName, purpose } = req.body;

  // Validate the request body using Joi schema
  const schema = Joi.object({
    purpose: Joi.string().valid('one', 'all').required().messages({
      'any.only': '"purpose" must be one of "one" or "all".',
      'any.required': '"purpose" is required.',
    }),
    campaignName: Joi.string().min(1).when('purpose', {
      is: 'one',
      then: Joi.required(),
      otherwise: Joi.forbidden(), // For 'all', forbid 'campaignName'
    }).messages({
      'string.base': '"campaignName" must be a string.',
      'string.min': '"campaignName" must be at least 1 character long.',
      'any.required': '"campaignName" is required for purpose "one".',
      'any.forbidden': '"campaignName" is not allowed for purpose "all".',
    }),
  });

  // Validate the incoming data
  const { error } = schema.validate(req.body);
  if (error) {
    // If validation fails, return an error response with the validation message
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    if (purpose === 'all') {
      // If purpose is 'all', delete all campaigns
      const [results] = await db.promise().query('DELETE FROM campaigns');
      return res.status(200).json({
        message: 'All campaigns deleted successfully.',
        affectedRows: results.affectedRows,
      });
    } else if (purpose === 'one') {
      // If purpose is 'one', delete a specific campaign
      const [result] = await db
        .promise()
        .query('DELETE FROM campaigns WHERE campaign_name = ?', [campaignName]);

      if (result.affectedRows > 0) {
        // Return success response if campaign is found and deleted
        return res.status(200).json({
          message: 'Campaign deleted successfully.',
          deletedCampaign: campaignName,
        });
      } else {
        // If campaign is not found, return a not found response
        return res.status(404).json({
          message: 'Campaign not found.',
        });
      }
    }
  } catch (err) {
    // Log error and return internal server error message
    console.error('Error processing request:', err);
    return res.status(500).json({ message: 'An error occurred while processing the request. Please try again later.' });
  }
});

// Handle the GET request to retrieve campaign(s)
app.get('/api/campaign/get/oneAll/:campaignName/:purpose', async (req, res) => { 
// Extract campaignName and purpose from the request body
  const { campaignName, purpose } = req.params;

  // Validate the request body using Joi
  const schema = Joi.object({
    // Validate purpose (either 'one' or 'all')
    purpose: Joi.string().valid('one', 'all').required().messages({
      'any.only': '"purpose" must be one of "one" or "all".',
      'any.required': '"purpose" is required.',
    }),
    // Validate campaignName (required only for 'one' purpose)
    campaignName: Joi.string().min(1).when('purpose', {
      is: 'one',
      then: Joi.required(),
      otherwise: Joi.forbidden(), // 'campaignName' is forbidden for 'all'
    }).messages({
      'string.base': '"campaignName" must be a string.',
      'string.min': '"campaignName" must be at least 1 character long.',
      'any.required': '"campaignName" is required for purpose "one".',
      'any.forbidden': '"campaignName" is not allowed for purpose "all".',
    }),
  });

  // If the validation fails, return a 400 status with the error message
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    // If purpose is 'all', fetch all campaigns from the database
    if (purpose === 'all') {
      const [results] = await db.promise().query('SELECT * FROM campaigns');
      return res.status(200).json({
        message: 'All promotion codes retrieved successfully.',
        promotionCodes: results,
      });
    } 
    // If purpose is 'one', fetch a specific campaign by campaignName
    else if (purpose === 'one') {
      const [result] = await db
        .promise()
        .query('SELECT * FROM campaigns WHERE campaign_name = ?', [campaignName]);

      // If the campaign is found, return it, else return 404
      if (result.length > 0) {
        return res.status(200).json({
          message: 'Promotion code retrieved successfully.',
          promotionCode: result[0],
        });
      } else {
        return res.status(404).json({
          message: 'Promotion code not found.',
        });
      }
    }
  } catch (err) {
    console.error('Error processing request:', err);
    return res.status(500).json({ message: 'An error occurred while processing the request. Please try again later.' });
  }
});

// Function to process campaign application based on category and amount
const processCampaignDetect = async (productCategory, totalAmount) => {
  try {
    // Validate productCategory and totalAmount
    if (!productCategory || typeof productCategory !== 'string' || productCategory.trim() === '') {
      throw new Error('Product category is invalid or missing.');
    }
    if (typeof totalAmount !== 'number' || totalAmount <= 0) {
      throw new Error('Total amount must be a positive number.');
    }

    // Fetch all campaigns that match the product category from the database
    const [campaigns] = await db
      .promise()
      .query('SELECT * FROM campaigns WHERE FIND_IN_SET(?, valid_categories)', [productCategory]);

    // If no campaigns are found, return an error
    if (campaigns.length === 0) {
      return {
        success: false,
        message: 'No campaigns found for the given product category.',
      };
    }

    // Initialize variables for discount calculations
    let discountAmount = 0;
    let finalAmount = totalAmount;

    // Process each campaign for the given category
    for (let campaign of campaigns) {
      console.log('Processing campaign:', campaign);
    
      // Check if the campaign is active and valid (within date range and not inactive)
      const currentDate = new Date();
      const startDate = new Date(campaign.start_date);
      const endDate = new Date(campaign.end_date);
    
      console.log('Current Date:', currentDate);
      console.log('Campaign Start Date:', startDate);
      console.log('Campaign End Date:', endDate);
    
      if (currentDate < startDate || currentDate > endDate) {
        console.log('Skipping campaign due to date range.');
        continue; // Skip expired or inactive campaigns
      }
    
      if (campaign.status === 'inactive') {
        console.log('Skipping campaign due to inactive status.');
        continue; // Skip inactive campaigns
      }
    
      if (campaign.usage_limit === 0) {
        console.log('Skipping campaign due to usage limit.');
        continue; // Skip campaigns that have reached usage limit
      }
    
      console.log('Valid campaign:', campaign);
    
      // Calculate discount based on campaign type (percentage or fixed)
      if (campaign.campaign_type === 'percentage') {
        discountAmount += (totalAmount * campaign.campaign_amount) / 100;
        console.log('Percentage Discount Applied:', discountAmount);
      } else if (campaign.campaign_type === 'fixed') {
        console.log('Fixed Discount Amount:', campaign.campaign_amount);
        discountAmount += campaign.campaign_amount;
      }
    
      console.log('Updated Discount Amount:', discountAmount);
    
      // Apply discount to the final amount
      finalAmount = totalAmount - discountAmount;
      console.log('Final Amount after Discount:', finalAmount);
    }
    
    // Return the result with the discount applied
    return {
      success: true,
      message: 'Campaigns applied successfully.',
      originalAmount: totalAmount,
      discountAmount,
      finalAmount,
    };
  } catch (err) {
    console.error('Error processing campaigns:', err.message);
    return {
      success: false,
      message: 'An error occurred while processing the campaigns. Please try again later.',
    };
  }
};



app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
