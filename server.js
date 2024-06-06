const express = require('express');
const socketIO = require('socket.io');
const http = require('http');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer=require('nodemailer');
const {v4: uuidv4} = require('uuid');
var crypto = require('crypto');
const Sib = require('sib-api-v3-sdk');
const multer = require('multer');

mongoose.set('strictQuery', true);

const app = express();


// const server = http.createServer(app);
// const io = socketIO(server);

//express app

app.use(cors());
app.use(express.json());
app.use(express.urlencoded())

const PORT = process.env.PORT;
const username = process.env.DB_USERNAME;
const password = process.env.DB_PASSWORD;

const uri = process.env.ATLAS_URI;


const Connection = async (username, password) => {
    // const URL = `mongodb://${username}:${password}@blogweb-shard-00-00.ch1hk.mongodb.net:27017,blogweb-shard-00-01.ch1hk.mongodb.net:27017,blogweb-shard-00-02.ch1hk.mongodb.net:27017/BLOG?ssl=true&replicaSet=atlas-lhtsci-shard-0&authSource=admin&retryWrites=true&w=majority`;
    try {
        await mongoose.connect(uri, { useNewUrlParser: true })
        console.log('Database connected successfully');
    } catch (error) {
        console.log('Error while connecting to the database ', error);
    }
};

Connection(username, password);

app.listen(PORT, () => console.log(`Server is running successfully on PORT ${PORT}`));

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true, 
        unique: true
    },
    phone: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true,
        minlength: 6,
    },
    role: {
        type: String,
        required: true,
    },
    verified: Boolean,
})

const User = new mongoose.model("User", userSchema);

const verificationtokenSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
    },
    token: {
		type: String,
		required: true,
	},
    createdAt: {
		type: Date,
		default: Date.now,
		expires: 1 * 86400, // 30 days
	},
});

const verificationtoken = new mongoose.model("verificationtoken", verificationtokenSchema);


const resettokenSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
    },
    token: {
		type: String,
		required: true,
	},
    createdAt: {
		type: Date,
		default: Date.now,
		expires: 1 * 86400, // 30 days
	},
});

const resettoken = new mongoose.model("resettoken", resettokenSchema);


const JWT_SECRET = process.env.ACCESS_SECRET_KEY;


//Routes
app.post("/login", async (req, res)=> {
    const { email, password} = req.body
    let user = await User.findOne({ email: req.body.email, verified: true });

    if (!user) {
        res.send({message: "User not registered/not verified"})
    }

    else {
        let match = await bcrypt.compare(req.body.password, user.password);
        if (match) {
            const payload = { email: user.email };
		    
            const accessToken = jwt.sign(
			payload,
			JWT_SECRET,
			{ expiresIn: '24h' }
		    );

            res.send({message: "Login Successful", accessToken: accessToken, user: user.email, role: user.role})
        } else {
            res.send({ message: "Incorrect credentials"})
        }
    }
}) 

var transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
      user: process.env.AUTH_EMAIL,
      pass: process.env.AUTH_PASS,
    },
    
  });


app.post("/register", async (req, res)=> {
    const { name, email, phone, password, role} = req.body
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    User.findOne({email: email}, async (err, user) => {

        if(user){
            res.send({message: "User already registered"})
        }
        else{
            const newUser = new User({ name: req.body.name, email: req.body.email, phone: req.body.phone, password: hashedPassword, verified: false, role: req.body.role});

            newUser.save(async err => {
                if(err) {
                    res.send(err)
                } else {
                    const otp = crypto.randomBytes(2).toString("hex");
                    const vtoken = new verificationtoken({ userId: newUser._id, token: otp});
                    await vtoken.save();

                    // sendEmail(newUser.email, "WANNA DIE", vtoken);
                    
                    const mailOptions = {
                        from: process.env.EMAIL_FROM,
                        to: newUser.email,
                        subject: 'Welcome to ThriftBasket!',
                        html: `<h2>Please use this OTP to verify your account</h2>
                                <h1>${otp}</h1>`
                      };
                    
                      transporter.sendMail(mailOptions, function(err, info) {
                        if (err) {
                          console.log(err);
                        } else {
                            res.send({message:"Please verify"});
                        }
                      });
                      res.send({message: "An OTP has been sent to your email. Please use it to get verified."})
                }
            })
        }
    })
    
})


app.post("/verify", async (req, res)=> {
    const { otp } = req.body
    let user = await verificationtoken.findOne({ token: otp });

    if (!user) {
        res.send({message: "Token is invalid"})
    }    

            await User.updateOne({_id: user.userId}, {$set: {verified: true}})

            res.send({message: "Verified"})
}) 


// send email Link For reset Password
app.post("/sendpasswordlink",async(req,res)=>{
    // console.log(req.body)

    const {email} = req.body;

    try {
        const userfind = await User.findOne({email:email});


        const userToken = await resettoken.findOne({ userId: userfind._id });
            if (userToken) await userToken.remove();


            const otp = crypto.randomBytes(2).toString("hex");
                    const rtoken = new resettoken({ userId: userfind._id, token: otp});
                    const setusertoken = await rtoken.save();

        if(setusertoken){
            const mailOptions = {
                from:process.env.FROM_EMAIL,
                to:email,
                subject:"Password Reset",
                html:`<h2>Please use this OTP to reset your password</h2>
                <h1>${otp}</h1>`
            }

            transporter.sendMail(mailOptions,(error,info)=>{
                if(error){
                    console.log("error",error);
                    res.send({message:"Could not send email"})
                }else{
                    console.log("Email sent",info.response);
                    res.send({message:"Email sent successfully"})
                }
            })

        }

    } catch (error) {
        res.send({message:"Invalid user"})
    }

});


app.post("/passwordreset",async(req,res)=>{

    const {otp, password} = req.body;

    try {
        const validtoken = await resettoken.findOne({token: otp});
        
        const validuser = await User.findOne({_id: validtoken.userId})

        if(validuser && validtoken){
            const newpassword = await bcrypt.hash(password,10);

            // const setnewuserpass = await User.updateOne({_id:validuser._id},{password:newpassword});
            await User.updateOne({_id: validuser._id}, {$set: {password: newpassword}})

            // setnewuserpass.save();
            res.send({message:"Password has been reset"})

        }else{
            res.send({message:"User does not exist"})
        }
    } catch (error) {
        res.send({error})
    }
})


app.post("/userprofile", async(req,res)=>{
    const token = req.body;
    console.log(token);
    try{
        const user = jwt.verify(token.token, JWT_SECRET);
        console.log(user);
        if(user == "Token Expired!"){
            return res.send({status: "error", data: "Token Expired!" })
        }
     
        const useremail = user.email; // accesses email
        User.findOne({email : useremail}).then((data) =>{ // finding user
            res.send({status: "OK!", data: data});
        })
        .catch((error) => {
            res.send({status: "Error!", data: error});
        });
    } catch (error) {}
}); 


const path = require('path');

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, path.join(__dirname, '../thrift-basket/mern-thrift/public/images/uploads'));
    },
    filename: function (req, file, cb) {
        console.log(file);
      cb(null, file.originalname);
    },
  });
  
  const upload = multer({ storage: storage });

  const productSchema = new mongoose.Schema({
    data: Buffer,
    contentType: String,
    name: String,
    fileName: String,
    price: Number,
    desc: String,
    category: String,
    uploader: String,
  });
  
  const Product = mongoose.model("Product", productSchema);

  const announcementSchema = new mongoose.Schema({
    title: String,
    description: String,
    data: Buffer,
    fileName: String,
    contentType: String,
    dateTime: Date,
    priceRange: String,
    uploader: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    interestedUsers: [
      {
        userEmail: String,
      }
    ],
    reminderSent: {
      type: Boolean,
      default: false,
    },
  });
  
  const Announcement = mongoose.model("Announcement", announcementSchema);

  app.post('/remindme/:id', async (req, res) => {
    const { id } = req.params;
    const token = req.body.token;
  
    try {

      const user = jwt.verify(token, JWT_SECRET);
      const userEmail = user.email;

    console.log(token)

    if (user === 'Token Expired!') {
      res.send({ status: 'error', data: 'Token Expired!' });
    }

      const announcement = await Announcement.findById(id);
  
      if (!announcement) {
        return res.status(404).send({ status: 'error', data: 'Announcement not found' });
      }
  
      // Check if the user's email is already in the interestedUsers array
      const isUserInterested = announcement.interestedUsers.some((user) => user.userEmail === userEmail);
  
      if (isUserInterested) {
        return res.status(200).send({ status: 'success', data: 'Reminder has already been set' });
      }
  
      // Add the user's email to the interestedUsers array
      announcement.interestedUsers.push({ userEmail });
  
      // Save the updated announcement
      await announcement.save();
  
      res.status(200).send({ status: 'success', data: 'You will be reminded via email' });
    } catch (error) {
      console.error(error);
      res.status(500).send({ status: 'error', data: 'Internal server error' });
    }
  });

  app.post('/remindmeforauction/:id', async (req, res) => {
    const { id } = req.params;
    const token = req.body.token;
  
    try {

      const user = jwt.verify(token, JWT_SECRET);
      const userEmail = user.email;

    console.log(token)

    if (user === 'Token Expired!') {
      res.send({ status: 'error', data: 'Token Expired!' });
    }

      const auction = await Auction.findById(id);
  
      if (!auction) {
        return res.status(404).send({ status: 'error', data: 'Announcement not found' });
      }
  
      // Check if the user's email is already in the interestedUsers array
      const isUserInterested = auction.interestedUsers.some((user) => user.userEmail === userEmail);
  
      if (isUserInterested) {
        return res.status(200).send({ status: 'success', data: 'Reminder has already been set' });
      }
  
      // Add the user's email to the interestedUsers array
      auction.interestedUsers.push({ userEmail });
  
      // Save the updated announcement
      await auction.save();
  
      res.status(200).send({ status: 'success', data: 'You will be reminded via email' });
    } catch (error) {
      console.error(error);
      res.status(500).send({ status: 'error', data: 'Internal server error' });
    }
  });


  const schedule = require('node-schedule');

  const job = schedule.scheduleJob('*/1 * * * *', async () => {
    try {
      const currentTime = new Date();
      const twentyFourHoursFromNow = new Date();
      twentyFourHoursFromNow.setHours(currentTime.getHours() + 24);
      
      const upcomingDrops = await Announcement.find({
        dateTime: {
          $gt: currentTime,
        $lt: twentyFourHoursFromNow,
        },
      });
  
      for (const drop of upcomingDrops) {
        // Retrieve interested user emails for the drop
        const interestedUserEmails = drop.interestedUsers.map((user) => user.userEmail);
        console.log(interestedUserEmails)
  
        // Retrieve user objects for the interested users
        const interestedUsers = await User.find({
          email: { $in: interestedUserEmails },
        });
  
        for (const user of interestedUsers) {
          console.log(user)
          const mailOptions = {
            from: process.env.EMAIL_FROM,
            to: user.email,
            subject: 'Upcoming Drop Reminder',
            text: `Hello ${user.name},\n\nThis is a reminder that the drop "${drop.title}" is happening on ${drop.dateTime}.\n\nDon't miss out on this exciting event! Keep an eye on our site!\n\nBest regards,\nTeam Thrift Basket`,
          };
  
          transporter.sendMail(mailOptions, function (err, info) {
            if (err) {
              console.log(err);
            } else {
              console.log(`Reminder email sent to ${user.email}`);
            }
          });
        }
      }

      console.log('Background task executed successfully');
    } catch (error) {
      console.error(error);
      res.send({ status: "Error!", data: error });
    }
  });
  
  console.log('Background task scheduled');

  const currentTime = new Date();
  const twentyFourHoursFromNow = new Date();
      twentyFourHoursFromNow.setHours(currentTime.getHours() + 24);

      console.log(currentTime);
      console.log(twentyFourHoursFromNow);

  const job2 = schedule.scheduleJob('*/1 * * * *', async () => {
    try {
      const currentTime = new Date();
      const twentyFourHoursFromNow = new Date();
      twentyFourHoursFromNow.setHours(currentTime.getHours() + 24);

      const upcomingAuctions = await Auction.find({
        startDate: {
          $gt: currentTime,
        $lt: twentyFourHoursFromNow,
        },
      });

      for (const auction of upcomingAuctions) {
        // Retrieve interested user emails for the drop
        const interestedUserEmails = auction.interestedUsers.map((user) => user.userEmail);
        console.log(interestedUserEmails)
  
        // Retrieve user objects for the interested users
        const interestedUsers = await User.find({
          email: { $in: interestedUserEmails },
        });
  
        for (const user of interestedUsers) {
          console.log(user)
          const mailOptions = {
            from: process.env.EMAIL_FROM,
            to: user.email,
            subject: 'Upcoming Auction Reminder',
            text: `Hello ${user.name},\n\nThis is a reminder that the drop "${auction.title}" starts on ${auction.startDate} and ends on ${auction.endDate}.\n\nDon't miss out on this exciting event! Keep an eye on our site!\n\nBest regards,\nTeam Thrift Basket`,
          };
  
          transporter.sendMail(mailOptions, function (err, info) {
            if (err) {
              console.log(err);
            } else {
              console.log(`Reminder email sent to ${user.email}`);
            }
          });
        }
      }
  
      console.log('Background task executed successfully');
    } catch (error) {
      console.error(error);
      res.send({ status: "Error!", data: error });
    }
  });
  
  console.log('Background task2 scheduled');
  

  const auctionSchema = new mongoose.Schema({
    title: {
      type: String,
      required: true,
    },
    description: {
      type: String,
      required: true,
    },
    data: Buffer,
    fileName: String,
    contentType: String,
    startingPrice: {
      type: Number,
      required: true,
    },
    currentPrice: {
      type: Number,
      default: null,
    },
    startDate: {
      type: Date,
      required: true,
    },
    endDate: {
      type: Date,
      required: true,
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    winningBidder: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null,
    },
    reminderSent: {
      type: Boolean,
      default: false,
    },
    interestedUsers: [
      {
        userEmail: String,
      }
    ],
    bids: [
      {
        userId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: 'User',
          required: true,
        },
        amount: {
          type: Number,
          required: true,
        },
        timestamp: {
          type: Date,
          required: true,
        },
      },
    ],
    closed: {
      type: Boolean,
      default: false,
    }
  });
  
  const Auction = mongoose.model('Auction', auctionSchema);


  app.post("/upload", upload.single("file"), async (req, res) => {
    let useremail;
    const token = req.body.uploader;

    // try {
        const user = jwt.verify(token, JWT_SECRET);
      
        useremail = user.email;
        // User.findOne({ email: useremail }).then((data) => {
          // console.log(data);
          const newProduct = new Product({
            data: req.file.buffer,
            contentType: req.file.mimetype,
            name: req.body.name,
            fileName:req.file.originalname,
            price: req.body.price,
            desc: req.body.desc,
            category: req.body.category,
            uploader: useremail,
          });

          newProduct.save(async err => {
            if (err) {
              res.send({err})
            } else {
              // console.log(savedProduct);
              res.status(200).json({ message: "Uploaded product successfully" });
            }
          }); 
    });

    app.post("/announcedrop", upload.single("file"), async (req, res) => {
        let useremail;
    const token = req.body.uploader;

    try {
        const user = jwt.verify(token, JWT_SECRET);
        // console.log(user);
        if (user == "Token Expired!") {
          res.send({ status: "error", data: "Token Expired!" });
        }
    
        useremail = user.email;
        const userr = await User.findOne({ email: useremail })
        const userid = userr._id;
        console.log(userid)
          // console.log(data);
      
          const newAnnouncement = new Announcement({
            title: req.body.title,
            description: req.body.description,
            data: req.file.buffer,
            contentType: req.file.mimetype,
            fileName: req.file.originalname,
            dateTime: req.body.dateTime,
            priceRange: req.body.priceRange,
            uploader: userid,
          });
      
          newAnnouncement.save(async (err, savedAnnouncement) => {
            if (err) {
              console.error(err);
              res.send({ status: "error", data: err });
            } else {
              console.log(savedAnnouncement);
              res.status(200).json({ message: "Uploaded announcement successfully" });
            }
          });

      } catch (error) {
        console.error(error);
        res.send({ status: "Error!", data: error });
        }
      });


      app.post("/announceauction", upload.single("file"), async (req, res) => {
        let useremail;
    const token = req.body.uploader;

    try {
        const user = jwt.verify(token, JWT_SECRET);
        // console.log(user);
        if (user == "Token Expired!") {
          res.send({ status: "error", data: "Token Expired!" });
        }
    
        useremail = user.email;
        const userr = await User.findOne({ email: useremail })
        const userid = userr._id;
        console.log(userid)
      
          const newAuction = new Auction({
            title: req.body.title,
            description: req.body.description,
            data: req.file.buffer,
            contentType: req.file.mimetype,
            fileName: req.file.originalname,
            startDate: req.body.startTime,
            endDate: req.body.endTime,
            startingPrice: req.body.startPrice,
            createdBy: userid,
          });
      
          newAuction.save(async (err, savedAuction) => {
            if (err) {
              console.error(err);
              res.send({ status: "error", data: err });
            } else {
              console.log(savedAuction);
              res.status(200).json({ message: "Uploaded announcement successfully" });
            }
          });
          
      } catch (error) {
        console.error(error);
        res.send({ status: "Error!", data: error });
        }
      });

    // Backend route to retrieve all products
    app.get("/flashproducts", async (req, res) => {
    try {
      const products = await Product.find({ price: { $lte: 800 } });

        // console.log(products);
        res.send(products);
    } catch (error) {
        console.error(error);
        res.send({ status: "Error!", data: error });
    }
  });

  app.get("/allproducts", async (req, res) => {
    try {
      const products = await Product.find();

        console.log(products);
        res.send(products);
    } catch (error) {
        console.error(error);
        res.send({ status: "Error!", data: error });
    }
  });

  app.get("/announcements", async (req, res) => {
    try {
      const currentDate = new Date();
        const announcements = await Announcement.find({ dateTime: { $gt: currentDate } }).populate('uploader', 'name');
        const announcementssWithUserName = announcements.map(announcement => {
          return {
            _id: announcement._id,
            title: announcement.title,
            uploader: announcement.uploader.name,
              description: announcement.description,
              fileName: announcement.fileName,
              dateTime: announcement.dateTime,
              priceRange: announcement.priceRange,
          };
        });
        res.send(announcementssWithUserName);
    } catch (error) {
        console.error(error);
        res.send({ status: "Error!", data: error });
    }
  });

  app.get("/mydrops", async (req, res) => {
      const token = req.headers.authorization.split(' ')[1];

  try {
    const user = jwt.verify(token, JWT_SECRET);

    if (user === 'Token Expired!') {
      res.send({ status: 'error', data: 'Token Expired!' });
    }

    const useremail = user.email;
    const userid = await User.findOne({email: useremail});

        const drops = await Announcement.find({ uploader: userid });
        res.send(drops);
    } catch (error) {
        console.error(error);
        res.send({ status: "Error!", data: error });
    }
  });

  app.get("/auctions", async (req, res) => {
    try {
      const currentDate = new Date();
      const auctions = await Auction.find({ endDate: { $gt: currentDate } }).populate('createdBy', 'name');
      const auctionsWithUserName = auctions.map(auction => {
        return {
          _id: auction._id,
          title: auction.title,
          createdBy: auction.createdBy.name,
            description: auction.description,
            fileName: auction.fileName,
            startDate: auction.startDate,
            endDate: auction.endDate,
            startingPrice: auction.startingPrice,
        };
      });
      res.send(auctionsWithUserName);
    } catch (error) {
      console.error(error);
      res.send({ status: "Error!", data: error });
    }
  });

  app.get("/bidpage/:auctionId", async (req, res) => {
    try {
      const auctionId = req.params.auctionId;
      const auction = await Auction.findById(auctionId)
      .populate({ path: "winningBidder", select: "name" })
      // .select("-closed");

    // const auction = {
    //   ...auctionn.toObject(),
    //   closed: auctionn.closed
    // };
  
      res.send(auction);
    } catch (error) {
      console.error(error);
      res.send({ status: "Error!", data: error });
    }
  });
  
  
  
  app.post("/startauction/:auctionId", async (req, res) => {
    try {
      const id = req.params.auctionId;
      console.log(id);
      const updatedAuction = await Auction.findOneAndUpdate(
        { _id: id },
        { startDate: new Date() },
        { new: true }
      );
      console.log(updatedAuction)
      res.send(updatedAuction);
    } catch (error) {
      console.error(error);
      res.send({ status: "Error!", data: error });
    }
  });

  app.post('/bid/:auctionId', async (req, res) => {
    const { auctionId } = req.params;
    const { token, amount, timestamp } = req.body;
  
    try {
    const user = jwt.verify(token, JWT_SECRET);

    if (user === 'Token Expired!') {
      res.send({ status: 'error', data: 'Token Expired!' });
    }

    console.log(token)

    const useremail = user.email;
    console.log(useremail)
    const userr = await User.findOne({email: useremail});
    const userid = userr._id;
      // Retrieve the auction document using the auction ID
      const auction = await Auction.findById(auctionId);
      if (!auction) {
        return res.status(404).json({ message: 'Auction not found' });
      }
  
      // Check if the bid amount is higher than the current highest bid or starting price
      if (amount <= auction.currentPrice || amount < auction.startingPrice) {
        return res.status(400).json({ message: 'Invalid bid amount' });
      }
  
      // Add the bid details to the bids array in the auction document
      auction.bids.push({ userId: userid, amount, timestamp });
      auction.currentPrice = amount;
      await auction.save();
      console.log(auction)
      return res.status(200).json({ message: 'Bid submitted successfully' });
    } catch (error) {
      console.error(error);
      return res.status(500).json({ message: 'Failed to submit bid' });
    }
  });


  // Replace with your auction model
  
  // Define the schedule rule to run every minute (adjust as needed)
  const scheduleRule = '*/1 * * * *';

  // Create the scheduled job
  const auctionJob = schedule.scheduleJob(scheduleRule, async () => {
    try {
      // Retrieve expired auctions
      const expiredAuctions = await Auction.find({
        endDate: { $lt: new Date() },
        closed: false,
      });
  
      // Process each expired auction
      expiredAuctions.forEach(async (auction) => {
        // Determine the winning bidder using the currentPrice field
        const winningBid = auction.bids.find((bid) => bid.amount === auction.currentPrice);
  
        if (winningBid) {
          // Close the auction
          auction.closed = true;
          auction.winningBidder = winningBid.userId;
          await auction.save();

          const user = await User.findOne({_id: auction.winningBidder})
          const email = user.email;
          console.log(email)

          const seller = await User.findOne({_id: auction.createdBy})
          const sellermail = seller.email;
          console.log(sellermail)

          const mailOptions = {
            from: process.env.EMAIL_FROM,
            to: email,
            subject: 'Auction Results!',
            text: `Hello ${user.name},\n\nYou have won the auction "${auction.title}".\n\nPlease reach out to the seller @ "${sellermail}"\n\nBest regards,\nTeam Thrift Basket`,
          };
  
          transporter.sendMail(mailOptions, function (err, info) {
            if (err) {
              console.log(err);
            } else {
              console.log(`Results sent to ${email}`);
            }
          });
  
          console.log(`Auction closed: ${auction._id}`);
        } else {
          console.log(`No winning bid found for auction: ${auction._id}`);
        }
      });
    } catch (error) {
      console.error('Error in auction scheduler:', error);
    }
  });
  
  // Start the scheduler
  console.log('Auction scheduler started.');
  
  
  // You can add any additional code or logic here if needed
  // For example, you may want to handle uncaught exceptions or perform any cleanup tasks
  


  app.get("/myauctions", async (req, res) => {
    const token = req.headers.authorization.split(' ')[1];

try {
  const user = jwt.verify(token, JWT_SECRET);

  if (user === 'Token Expired!') {
    res.send({ status: 'error', data: 'Token Expired!' });
  }

  const useremail = user.email;
  const userid = await User.findOne({email: useremail});

      const auctions = await Auction.find({ createdBy: userid });
      res.send(auctions);
  } catch (error) {
      console.error(error);
      res.send({ status: "Error!", data: error });
  }
});


app.get("/myproducts", async (req, res) => {
  const token = req.headers.authorization.split(' ')[1];

try {
const user = jwt.verify(token, JWT_SECRET);

if (user === 'Token Expired!') {
  res.send({ status: 'error', data: 'Token Expired!' });
}

const useremail = user.email;

    const products = await Product.find({ uploader: useremail });
    res.send(products);
} catch (error) {
    console.error(error);
    res.send({ status: "Error!", data: error });
}
});

app.get("/productdetails/:productId", async (req, res) => {
  try {
    const productId = req.params.productId;
    if (!mongoose.Types.ObjectId.isValid(productId)) {
      // Check if the productId is a valid ObjectId
      return res.status(400).json({ status: "Error", message: "Invalid product ID" });
    }

    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ status: "Error", message: "Product not found" });
    }

    const reviews = await Review.find({productId: productId})

    const user = await User.findOne({ email: product.uploader});
    const username = user.name;
    // console.log(username)

    // console.log(product);
    res.send({product: product, user: username, reviews: reviews});
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: "Error", message: "Internal server error" });
  }
});

app.get("/profile/:username", async(req,res)=>{
  const username = req.params.username;
  console.log(username);
  try{
    const user = await User.findOne({ name: username });
    console.log(user.email);
    const products = await Product.find({uploader: user.email}).maxTimeMS(20000);
    let orderno;
    
    if (user.role === "buyer")
    {
      orderno = await Order.countDocuments({ email: user.email });
    }
    else {
      orderno = await Order.countDocuments({ sellerEmail: user.email });
    }

    const reviews = await Review.find({ sellerId: user._id });

    console.log(products);
    res.send({user: user, products: products, orders: orderno, reviews: reviews});
  } catch (error) {}
}); 



app.get("/category/:slug", async (req, res) => {
  const slug = req.params.slug;
  console.log(slug);

  try {
    // Fetch products from the database based on the category slug
    const products = await Product.find({ category: slug });
    if (!products) {
      return res.status(404).json({ status: "Error", message: "Product not found" });
    }

    // console.log(product);
    res.send(products);
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: "Error", message: "Internal server error" });
  }
});



const cartSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  items: [
    {
      productId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Product',
        required: true
      },
      name: {
        type: String,
        required: true
      },
      price: {
        type: Number,
        required: true
      },
      quantity: {
        type: Number,
        // required: true
      }
    }
  ]
});

const Cart = mongoose.model('Cart', cartSchema);


app.post('/cart/add', async (req, res) => {
  const { _id, name, price, quantity } = req.body;
  const token = req.headers.authorization.split(' ')[1];

  try {
    const user = jwt.verify(token, JWT_SECRET);

    if (user === "Token Expired!") {
      res.send({ status: "error", data: "Token Expired!" });
    }

    const useremail = user.email;
    const userr = await User.findOne({ email: useremail });
    const userid = userr._id;

    const newItem = {
      productId: _id,
      name: name,
      price: price,
      quantity: quantity,
    };

    const cart = await Cart.findOne({ userId: userid });

    if (cart) {
      const existingItem = cart.items.find((item) => item.productId.toString() === _id);
      
      if (existingItem) {

        Object.assign(
          existingItem,
          newItem);

      } else {
        cart.items.push(newItem);
      }

      await cart.save();
    } else {
      
      const newCart = new Cart({
        userId: userid,
        items: [newItem]
      });

      await newCart.save();
    }

    res.status(200).send(cart.items)

  } catch (error) {
    console.error(error);
    res.send({ status: "Error!", data: error });
  }
});


app.post('/cart/addfromcart', async (req, res) => {
  const { productId, name, price, quantity } = req.body;
  const token = req.headers.authorization.split(' ')[1];

  try {
    const user = jwt.verify(token, JWT_SECRET);

    if (user === "Token Expired!") {
      res.send({ status: "error", data: "Token Expired!" });
    }

    const useremail = user.email;
    const userr = await User.findOne({ email: useremail });
    const userid = userr._id;

    const newItem = {
      productId: productId,
      name: name,
      price: price,
      quantity: quantity,
    };

    const cart = await Cart.findOne({ userId: userid })

    if (cart) {

      const existingItem = cart.items.find((item) => item.productId._id.toString() === productId);
      
        Object.assign(existingItem, newItem);
        console.log("existing item after", existingItem);

      await cart.save();

      const populatedItems = await Cart.populate(cart, { path: 'items.productId', select: 'fileName' });

      const transformedItems = populatedItems.items.map((item) => {
        const { productId, name, price, quantity } = item;
        const fileName = productId.fileName; // Access the 'fileName' field directly

        return {
          productId: productId._id,
          name,
          price,
          quantity,
          fileName: fileName
        };
      });

      res.status(200).send(transformedItems);
      console.log(cart);
    } 
  } catch (error) {
    console.error(error);
    res.send({ status: "Error!", data: error });
  }
});


app.post('/cart/remove', async (req, res) => {
  const { productId } = req.body;
  const token = req.headers.authorization.split(' ')[1];

  try {
    const user = jwt.verify(token, JWT_SECRET);

    if (user === "Token Expired!") {
      res.send({ status: "error", data: "Token Expired!" });
    }

    const useremail = user.email;
    const userr = await User.findOne({ email: useremail });
    const userid = userr._id;

    console.log(userid);

    const cart = await Cart.findOne({ userId: userid }).populate({
  path: 'items.productId',
  select: 'fileName',
});

    if (cart) {
      
      cart.items = cart.items.filter((item) => item.productId._id.toString() !== productId);
      await cart.save();

      const transformedItems = cart.items.map((item) => {
        const { productId, name, price, quantity } = item;
        const { fileName } = productId; 

        return {
          productId: productId._id,
          name,
          price,
          quantity,
          fileName: fileName 
        };
      });

      res.status(200).send(transformedItems);
    } else {
      res.status(200).send('Cart is empty');
    }
  } catch (error) {
    console.error(error);
    res.send({ status: "Error!", data: error });
  }
});


app.post('/cart/decreaseqty', async (req, res) => {
  const { productId } = req.body;
  const token = req.headers.authorization.split(' ')[1];

  try {
    const user = jwt.verify(token, JWT_SECRET);

    if (user === "Token Expired!") {
      res.send({ status: "error", data: "Token Expired!" });
    }

    const useremail = user.email;
    const userr = await User.findOne({ email: useremail });
    const userid = userr._id;

    console.log(userid);

    const cart = await Cart.findOne({ userId: userid }).populate({
      path: 'items.productId',
      select: 'fileName',
    });

    if (cart) {
      
      const item = cart.items.find((item) => item.productId._id.toString() === productId);

      if (item) {
        
        if (item.quantity === 1) {
          
          cart.items = cart.items.filter((item) => item.productId._id.toString() !== productId);
        } else {
          
          item.quantity -= 1;
        }

        await cart.save();

        const transformedItems = cart.items.map((item) => {
          const { productId, name, price, quantity } = item;
          const { fileName } = productId; 
  
          return {
            productId: productId._id,
            name,
            price,
            quantity,
            fileName: fileName 
          };
        });

        res.status(200).send(transformedItems);
      } else {
        res.status(200).send('Item not found in cart');
      }
    } else {
      res.status(200).send('Cart is empty');
    }
  } catch (error) {
    console.error(error);
    res.send({ status: "Error!", data: error });
  }
});


app.get('/cart', async (req, res) => {
  const token = req.headers.authorization.split(' ')[1];

  try {
    const user = jwt.verify(token, JWT_SECRET);

    if (user === 'Token Expired!') {
      res.send({ status: 'error', data: 'Token Expired!' });
    }

    const useremail = user.email;
    const userr = await User.findOne({ email: useremail });
    const userid = userr._id;

    console.log(userid);

    const cart = await Cart.findOne({ userId: userid }).populate({
      path: 'items.productId',
      select: 'fileName',
    });

    if (cart) {

      const transformedItems = cart.items.map((item) => {
        const { productId, name, price, quantity } = item;
        const { fileName } = productId; 

        return {
          productId: productId._id,
          name,
          price,
          quantity,
          fileName: fileName 
        };
      });

      res.status(200).send(transformedItems);
      console.log(cart);
    } else {
      res.status(200).send([]);
    }
  } catch (error) {
    console.error(error);
    res.send({ status: 'Error!', data: error });
  }
});



// io.on('connection', (socket) => {
//   console.log('New client connected');

//   // Example event: handle new bid
//   socket.on('newBid', (bidData) => {
//     // Process the bid and emit the updated bid to all connected clients
//     const updatedBid = processBid(bidData);
//     io.emit('bidUpdate', updatedBid);
//   });

//   // Handle disconnection
//   socket.on('disconnect', () => {
//     console.log('Client disconnected');
//   });
// });


const orderSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
  },
  phone: {
    type: String,
    required: true,
  },
  address: {
    type: String,
    required: true,
  },
  totalPrice: {
    type: Number,
    required: true,
  },
  
  cart: [
    {
      productId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Product',
        required: true
      },
      sellerEmail: {
        type: String,
        required: true,
      },
      name: {
        type: String,
        required: true
      },
      price: {
        type: Number,
        required: true
      },
      quantity: {
        type: Number,
        // required: true
      }
    }
  ]
});

const Order = mongoose.model('Order', orderSchema);

const bodyParser = require('body-parser')
app.use(bodyParser.urlencoded({ extended: false }))

// parse application/json
app.use(bodyParser.json());

const SSLCommerzPayment = require('sslcommerz-lts')

//sslcommerz init
app.post('/checkout/:totalprice', async(req, res) => {

  // const tran_id = generateUniqueTransactionId();

  const { email, phone, address } = req.body.user;
  const { userCart } = req.body;
  const totalPrice = parseFloat(req.params.totalprice);

  const user = await User.findOne({email: email});
  const userid = user.id;

    const data = {
      total_amount: totalPrice,
        currency: 'BDT',
        tran_id: 'ref',
        success_url: 'http://localhost:9002/ssl-payment-success',
        fail_url: 'http://localhost:9002/ssl-payment-fail',
        cancel_url: 'http://localhost:9002/ssl-payment-cancel',
        cus_email: email,
        shipping_method: 'No',
        product_name: 'Happy Purchasing!', // Update the description here
        product_category: 'Electronic',
        product_profile: 'Happy Purchasing!',
    cus_name: 'Customer Name',
    cus_email: 'cust@yahoo.com',
    cus_add1: 'Dhaka',
    cus_add2: 'Dhaka',
    cus_city: 'Dhaka',
    cus_state: 'Dhaka',
    cus_postcode: '1000',
    cus_country: 'Bangladesh',
    cus_phone: '01711111111',
    cus_fax: '01711111111',
    multi_card_name: 'mastercard',
    value_a: 'ref001_A',
    value_b: 'ref002_B',
    value_c: 'ref003_C',
    };

    // const sslcz = new SSLCommerzPayment(process.env.STORE_ID, process.env.STORE_PASSWORD, false)

    const populatedCart = await Promise.all(
      userCart.map(async (cartItem) => {
        const product = await Product.findById(cartItem.productId);
        const email = product.uploader;
        console.log(email)
  
        return {
          ...cartItem,
          sellerEmail: email,
        };
      })
    );
  
    const order = new Order({
      email,
      phone,
      address, // Assuming you want to save the first seller's email in the order as before
      totalPrice,
      cart: populatedCart,
      // Other payment/order details
    });

    try {
      await order.save();
      console.log(order)
    } catch (error) {
      console.error(error);
    }


    const cart = await Cart.findOneAndUpdate(
      { userId: userid }, // Find the cart by userId
      { $set: { items: [] } }, // Set the items array to an empty array
      { new: true } // Return the updated cart
    );

    const sslcommerz = new SSLCommerzPayment(process.env.STORE_ID, process.env.STORE_PASSWORD, false);
  try {
    const response = await sslcommerz.init(data);
    if (response?.GatewayPageURL) {
      return res.status(200).json({
        redirectUrl: response.GatewayPageURL // Send the redirect URL to the frontend
      });
    } else {
      console.log(response); // Log the response for debugging
      return res.status(400).json({
        message: "Session was not successful"
      });
    }
  } catch (error) {
    console.error(error); // Log any potential errors for debugging
    return res.status(500).json({
      message: "Failed to initiate SSLCommerz session"
    });
  }
});



app.post("/ssl-payment-notification", async (req, res) => {

  /** 
  * If payment notification
  */

  return res.status(200).json(
    {
      data: req.body,
      message: 'Payment notification'
    }
  );
})

app.post('/ssl-payment-success', (req, res) => {
  res.redirect("http://localhost:3000/paymentsuccess")
});


app.post("/ssl-payment-fail", async (req, res) => {

  /** 
  * If payment failed 
  */

  return res.status(200).json(
    {
      data: req.body,
      message: 'Payment failed'
    }
  );
})


app.get('/purchases', async (req, res) => {
  const token = req.headers.authorization.split(' ')[1];

  try {
    const user = jwt.verify(token, JWT_SECRET);

    if (user === 'Token Expired!') {
      res.send({ status: 'error', data: 'Token Expired!' });
    }

    const useremail = user.email;

    try {
      const orders = await Order.find({ email: useremail }).populate({
        path: 'cart.productId',
        select: 'fileName',
      });

      const purchasePromises = orders.map(async (order) => {
        const purchases = await Promise.all(
          order.cart.map(async (item) => {
            const { name, price, quantity, sellerEmail } = item;
            const fileName = item.productId.fileName;
            
            // Look up the seller by email in the User schema
            const seller = await User.findOne({ email: sellerEmail });
            const sellerName = seller ? seller.name : null;
      
            return [name, price, quantity, fileName, sellerName];
          })
        );
      
        return [purchases];
      });
      


      const purchases = await Promise.all(purchasePromises);
res.status(200).json(purchases);

    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Failed to fetch purchases' });
    }
  } catch {
    res.status(500).json({ message: 'Failed to fetch purchases' });
  }
});


app.get('/sales', async (req, res) => {
  const token = req.headers.authorization.split(' ')[1];

  try {
    const user = jwt.verify(token, JWT_SECRET);

    if (user === 'Token Expired!') {
      res.send({ status: 'error', data: 'Token Expired!' });
    }

    const useremail = user.email;

    try {
      const orders = await Order.find({}).populate({
        path: 'cart.productId',
        select: 'fileName',
      });

      const salesPromises = orders.map(async (order) => {
        const buyer = await User.findOne({ email: order.email });
        const buyerName = buyer.name;

        const sales = order.cart.map((item) => {
          const { name, price, quantity } = item;
          const fileName = item.productId.fileName;

          return [name, price, quantity, fileName];
        });

        return [buyerName, sales];
      });


      const sales = await Promise.all(salesPromises);
res.status(200).json(sales);

    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Failed to fetch purchases' });
    }
  } catch {
    res.status(500).json({ message: 'Failed to fetch purchases' });
  }
});

const reviewSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  productId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Product',
    required: true
  },
  review: {
    type: String,
    required: true
  }
});

const Review = mongoose.model('Review', reviewSchema);


app.post('/reviews', async (req, res) => {
  const { token, purchaseId, review } = req.body;

  console.log(purchaseId)

  try {

    const user = jwt.verify(token, JWT_SECRET);

    if (user === 'Token Expired!') {
      res.send({ status: 'error', data: 'Token Expired!' });
    }

    const useremail = user.email;
    // Assuming you have a Purchase model/schema defined
    const userr = await User.findOne({email: useremail});
    const userId = userr._id;

    const prod = await Product.findOne({name: purchaseId})
    const productId = prod._id;
    // console.log(seller._id)
    // console.log(sellerId)

    if (!userId) {
      return res.status(404).json({ message: 'Purchase not found' });
    }

    // Add the review to the purchase
    const newReview = new Review({
      userId: userId,
      productId: productId,
      review: review,
  });
    await newReview.save();

    return res.status(200).json({ message: 'Review submitted successfully' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Failed to submit review' });
  }
});


app.get('/seerev', async (req, res) => {

    const token = req.headers.authorization.split(' ')[1];
  try {
    
    const user = jwt.verify(token, JWT_SECRET);

    console.log(token)

    if (user === 'Token Expired!') {
      res.send({ status: 'error', data: 'Token Expired!' });
    }

    // console.log(user.email);
    // console.log(user.email.email)

    const seller = await User.findOne({email: user.email});
    const sellerId = seller._id;

    console.log(seller._id)

    // Assuming you have a Review model/schema defined
    const reviews = await Review.find({sellerId: sellerId});
    console.log(reviews.review) // Retrieve all reviews and populate the sellerId field with the name of the seller
    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).json(reviews);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Failed to fetch reviews' });
  }
});