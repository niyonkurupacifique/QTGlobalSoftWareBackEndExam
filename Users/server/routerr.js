import {Router} from 'express'
import sql from 'mssql';
import cors from 'cors';
import express from 'express'
 import protect from './modules/auth.js';
 import { createJWT } from './modules/auth.js';
 import { hashPassword } from './modules/auth.js';
 import { comparePassword } from './modules/auth.js';
 import bcrypt from 'bcrypt'
 import jwt from 'jsonwebtoken'
 import nodemailer  from "nodemailer";
 import Mailgen from 'mailgen';
 import fetch from 'node-fetch';
const router=Router()
// Configuration for your database


const protectt = (req, res, next) => {
    const bearer = req.headers.authorization;
  
    if (!bearer || !bearer.startsWith('Bearer ')) {
      return res.status(401).end();
    }
  
    const token = bearer.split('Bearer ')[1].trim();
    try {
      const payload = verifyJWT(token);
      next();
    } catch (e) {
      return res.status(401).end();
    }
  }
  
var config = {
    user: 'NIYONKURU',
    password: '1234567',
    server: 'DESKTOP-TO2UMIT\\SQLEXPRESS',
    database: 'UsersManagementDB',
    synchronize: true,
    trustServerCertificate: true,
};
router.use(cors()); 
router.use(express.json()); 


  router.post('/register', async function (req, res) {
   
    var email = req.body.email;
    
   

      
     
    const currentDate = new Date();
    const isoDateString = currentDate.toISOString();
    var name = req.body.name;
    var username = req.body.username;
    var plainPassword = req.body.password;
   
    

    var recordedDate = isoDateString;
    var password = await hashPassword(plainPassword);

    const nameRegex = /^[A-Za-z\-']{2,}(?:\s[A-Za-z\-']{2,})*$/;
    const usernameRegex = /^[A-Za-z0-9_\-]{4,20}$/;
    const emailRegex = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;

    if (!nameRegex.test(name)) {
        return res.status(400).json({ errorMessage: 'Invalid name.' });
    }
    if (!usernameRegex.test(username)) {
        return res.status(400).json({ errorMessage: 'Invalid username.' });
    }
    if (!emailRegex.test(email)) {
        return res.status(400).json({ errorMessage: 'Invalid email.' });
    }
    if (plainPassword.length < 8) {
        return res.status(400).json({ errorMessage: 'Password must be at least 8 characters.' });
    }

    
    const emailCheckQuery = `
        SELECT COUNT(*) AS emailCount
        FROM UsersTable
        WHERE Email = @email
    `;

    
    sql.connect(config, function (err) {
        if (err) {
            console.log(err);
            res.status(500).send('Error occurred while connecting to the database.');
        } else {
            var request = new sql.Request();

           
            request.input('email', sql.VarChar, email);

           
            request.query(emailCheckQuery, function (err, result) {
                if (err) {
                    console.log(err);
                    return res.status(500).json({ errorMessage: 'Error occurred while checking email existence.' });
                }

                const emailCount = result.recordset[0].emailCount;

                if (emailCount > 0) {
                    return res.status(400).json({ errorMessage: 'Email already in use.' });
                }

               
                var sqlQuery = `
                    INSERT INTO UsersTable (
                        Names, UserName, Password, Email,  RecordedDate)
                    OUTPUT INSERTED.idRecord
                    VALUES (
                        @name, @username, @password, @email,  @recordedDate)
                `;

                var request = new sql.Request();

              
                request.input('name', sql.VarChar, name);
                request.input('UserName', sql.VarChar, username);
                request.input('Password', sql.NVarChar, password);
                request.input('email', sql.VarChar, email);
                request.input('recordedDate', sql.VarChar, recordedDate);

               
                request.query(sqlQuery, function (err, result) {
                    if (err) {
                        if (err.number === 2601 || err.number === 2627) {
                          
                            return res.status(400).json({ errorMessage: 'Oops! It looks like a customer with that Customer Id already exists.' });
                        }
                        console.log(err);
                        return res.status(500).json({ errorMessage: 'Error occurred while inserting data into the database  try again' });
                    }

                    if (result && result.recordset && result.recordset.length > 0) {
                      
                        var insertedIdRecord = result.recordset[0].idRecord;

                        const user = {
                            id: insertedIdRecord,
                            username: username
                        };
                        const token = createJWT(user);
                        return res.status(201).json({ successMessage: 'Data submitted successfully.', id: insertedIdRecord, names: name, email: email, username: username, recordedDate: recordedDate, token: token });
                    } else {
                        return res.status(500).json({ errorMessage: 'No idRecord returned after insertion.' });
                    }
                });
            });
        }
    });
});


const getUserByEmail = (email) => {
    return new Promise((resolve, reject) => {
        sql.connect(config, (err) => {
            if (err) {
                console.error(err);
                reject(err);
                return;
            }

            const request = new sql.Request();
            request.input('email', sql.VarChar, email);

            const query = `
                SELECT * FROM UsersTable WHERE Email = @email;
            `;

            request.query(query, (err, result) => {
                sql.close(); 

                if (err) {
                    console.error(err);
                    reject(err);
                } else if (result.recordset.length === 0) {
                    resolve(null);
                } else {
                    resolve(result.recordset[0]);
                   
                }
            });
        });
    });
};

 router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ errorMessage: 'Email and password are required.' });
    }

    try {
        const user = await getUserByEmail(email);

        if (!user) {
            return res.status(401).json({ errorMessage: 'User not found. Please register first.' });
        }

        const isPasswordValid = await bcrypt.compare(password,user.Password); 

        if (!isPasswordValid) {
            return res.status(401).json({ errorMessage: 'Invalid password.'+user.Password+" "+password, });
        }

        const payload = {
            id:user.IdRecord,
            email: user.Email,
            username: user.UserName,
        };
         console.log("user id is:",user.IdRecord)
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
       

        return res.status(200).json({ successMessage: 'Login successful.', token:token,email:user.Email,names:user.Names,id:user.IdRecord});
    } catch (error) {
        console.error(error);
        return res.status(500).json({ errorMessage: 'An error occurred during login.' });
    }


});

router.get('/getallprojects', function (req, res) {
   
    var sqlQuery = `
        SELECT DISTINCT projectsName
        FROM projects
        ORDER BY  projectsName ASC
    `;

    // Connect to your database
    sql.connect(config, function (err) {
        if (err) {
            console.log(err);
            res.status(500).send('Error occurred while connecting to the database.');
        } else {
            // Create a new Request object
            var request = new sql.Request();

            // Query the database
            request.query(sqlQuery, function (err, recordset) {
                if (err) {
                    console.log(err);
                    res.status(500).send('Error occurred while fetching data from the database.');
                } else {
                    if (recordset && recordset.recordset.length > 0) {
                        // If there are records, send the unique ages back
                        var uniqueProject = recordset.recordset.map(item => item.projectsName);
                        res.send({ projects:uniqueProject });
                    } else {
                        // If no records found, send an appropriate response
                        res.status(404).send('No data found.');                        
                    }
                }
            });
        }
    });
});



 
 router.get('/getallusers', function (req, res) {
   
    var sqlQuery = `
        SELECT DISTINCT Names
        FROM UsersTable
        ORDER BY  Names ASC
    `;

    // Connect to your database
    sql.connect(config, function (err) {
        if (err) {
            console.log(err);
            res.status(500).send('Error occurred while connecting to the database.');
        } else {
            // Create a new Request object
            var request = new sql.Request();

            // Query the database
            request.query(sqlQuery, function (err, recordset) {
                if (err) {
                    console.log(err);
                    res.status(500).send('Error occurred while fetching data from the database.');
                } else {
                    if (recordset && recordset.recordset.length > 0) {
                        // If there are records, send the unique ages back
                        var uniqueAges = recordset.recordset.map(item => item.Names);
                        res.send({ ages: uniqueAges });
                    } else {
                        // If no records found, send an appropriate response
                        res.status(404).send('No data found.');                        
                    }
                }
            });
        }
    });
});




 router.post('/createTask',protect, async function (req, res) {
   
    var name = req.body.name;
    var startDate = req.body.startDate;
    var endDate = req.body.endDate;
    var assignee = req.body.assignee;
    var projects = req.body.projects;
    var description = req.body.description;
    var priority = req.body.priority;
    var attach = req.body.attach;
    
   

    var sqlQuery = `
        INSERT INTO createTaskTable (
           name,startDate,endDate,assignee,projects,description,priority,attach)
           
        VALUES (
            @name, @startDate, @endDate, @assignee, @projects,
            @description, @priority, @attach )
    `;
    sql.connect(config, function (err) {
        if (err) {
            console.log(err);
            res.status(500).send('Error occurred while connecting to the database.');
        } else {
           
            var request = new sql.Request();
            request.input('name', sql.VarChar,name);
            request.input('startDate', sql.VarChar,startDate);
            request.input('endDate', sql.VarChar,endDate);
            request.input('assignee', sql.NVarChar,assignee);
            request.input('projects', sql.VarChar,projects);
            request.input('description', sql.VarChar,description);
            request.input('priority', sql.VarChar,priority);
            request.input('attach', sql.VarChar,attach);
           
           

           
            request.query(sqlQuery, function (err, result) {
                if (err) {
                     
                    
                    
                    console.log(err);
                return    res.status(500).json({errorMessage:'Error occurred while Recording data into the database '})
                } else {               

                 return   res.status(201).json({successMessage:'recorded successfully.'}); // Send a success response
                }
            });
        }
    });

});


router.get('/taskDetails', function (req, res) {
    var sqlQuery = `
        SELECT * FROM createTaskTable
    `;

   
    sql.connect(config, function (err) {
        if (err) {
            console.log(err);
            res.status(500).send('Error occurred while connecting to the database.');
        } else {
           
            var request = new sql.Request();

            request.query(sqlQuery, function (err, recordset) {
                if (err) {
                    console.log(err);
                    res.status(500).send('Error occurred while fetching data from the database.');
                } else {
                   res.send(recordset)
                }
            });
        }
    });
});


export default router
