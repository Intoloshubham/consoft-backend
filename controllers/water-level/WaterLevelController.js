import fs from 'fs';
import { ObjectId } from 'mongodb';
import { WaterLevel } from '../../models/index.js';
import CustomErrorHandler from '../../services/CustomErrorHandler.js';
import CustomFunction from '../../services/CustomFunction.js';
import CustomSuccessHandler from '../../services/CustomSuccessHandler.js';

const WaterLevelController = {

    async getLedStatus(req, res, next){
        let documents;
        try {
            documents = await WaterLevel.findOne({unique_id:req.params.unique_id}).select('led_status -_id');
        } catch (err) {
            return next(CustomErrorHandler.serverError());
        }
        return res.json({status:200, data:documents});
    },

    async getSumpStatus(req, res, next){
        let documents;
        try {
            documents = await WaterLevel.findOne({unique_id:req.params.unique_id}).select('sump_status -_id');
        } catch (err) {
            return next(CustomErrorHandler.serverError());
        }
        return res.json({status:200, data:documents});
    },

    async updateLedStatus(req, res, next){

        const water_level_id = await getWaterLevelId(req.params.unique_id);

        const {led_status} = req.body;
        try {
            const filter = { _id: water_level_id};
            const options = { upsert: true };
            const updateDoc = {
                $set: {
                    led_status: led_status
                }
            };
            const result = await WaterLevel.updateOne(filter, updateDoc, options);
            
        } catch (err) {
            return next(CustomErrorHandler.serverError());
        }
        return res.send(CustomSuccessHandler.success('Led status updated successfully'));
    },

    async updateSumpStatus(req, res, next){

        const water_level_id = await getWaterLevelId(req.params.unique_id);

        const {sump_status} = req.body;
        try {
            const filter = { _id: water_level_id};
            const options = { upsert: true };
            const updateDoc = {
                $set: {
                    sump_status: sump_status
                }
            };
            const result = await WaterLevel.updateOne(filter, updateDoc, options);
            
        } catch (err) {
            return next(CustomErrorHandler.serverError());
        }
        return res.send(CustomSuccessHandler.success('Sump status updated successfully'));
    },

    async getWaterLevel(req, res, next){
        let documents;
        try {
            documents = await WaterLevel.findOne({unique_id:req.params.unique_id}).select('-__v');
        } catch (err) {
            return next(CustomErrorHandler.serverError());
        }
        return res.json({status:200, data:documents});
    },

    async updateWaterLevel(req, res, next){
        const water_level_id = await getWaterLevelId(req.params.unique_id)
        try {
            const { water_level, ph_level } = req.body;
            const filter = { _id: water_level_id};
            const options = { upsert: true };
            const updateDoc = {
                $set: {
                    water_level: water_level,
                    ph_level: ph_level
                }
            };
            const result = await WaterLevel.updateOne(filter, updateDoc, options);
            
        } catch (err) {
            return next(CustomErrorHandler.serverError());
        }
        return res.send(CustomSuccessHandler.success('Water Level updated successfully'));
    },

    async getWaterLevelImage(req, res, next){
        const image_file_name = "water_"+req.params.unique_id;
        const base64_string = fs.createReadStream('uploads/files/'+image_file_name+'.txt','utf-8');
        base64_string.pipe(res);
    },

    async saveWaterLevelImage(req, res, next){
        const {image} = req.body;
        console.log(image)
        try {
            const replace_2F = image.replace(/%2F/g, '/'); // %2F = /
            const final_image = replace_2F.replace(/%2B/g, '+'); // %2B = +
            const image_file_name = "water_"+req.params.unique_id;

            const date = CustomFunction.currentDate();
            const time = new Date().toLocaleTimeString("en-US", {hour: '2-digit', minute: "2-digit", second:"2-digit", hour12: true, timeZone: "Asia/kolkata"});

            fs.writeFileSync('uploads/files/'+image_file_name+'.txt', JSON.stringify({image:'data:image/png;base64,'+final_image, date:date, time:time}));
            fs.writeFileSync("uploads/images/"+image_file_name+'.gif', final_image, {encoding: 'base64'}, function(err){
                console.log('File created');
            });
        } catch (error) {
            return next(CustomErrorHandler.serverError());
        }
        return res.send(CustomSuccessHandler.success('Water Level image frames updated successfully'));
    }
    
}

async function getWaterLevelId(unique_id){
    const exist = await WaterLevel.exists({ unique_id: unique_id });
    let water_level_id;
    if (!exist) {
        const water = new WaterLevel({
            unique_id: unique_id,
        });
        const result = await water.save();
        water_level_id = result._id;
    } else {
        water_level_id = exist._id;
    }
    return water_level_id;
}

export default WaterLevelController;


// import { WaterLevel } from '../../models/index.js';
// import CustomSuccessHandler from '../../services/CustomSuccessHandler.js';
// import CustomErrorHandler from '../../services/CustomErrorHandler.js';
// import CustomFunction from '../../services/CustomFunction.js';
// import multer from 'multer';
// import path from 'path';
// import fs from 'fs';
// import { encode, decode } from 'node-base64-image';
// import { ObjectId } from 'mongodb';

// const date = CustomFunction.currentDate();
// const time = CustomFunction.currentTime();

// // const storage = multer.diskStorage({
// //     destination: (req, file, cb) => cb(null, 'assets/images/water_level/uploads/'),
// //     filename: (req, file, cb) => {
// //         const uniqueName = `${Date.now()}-${Math.round(
// //             Math.random() * 1e9
// //         )}${path.extname(file.originalname)}`;
// //         // 3746674586-836534453.png
// //         // console.log(req)
// //         cb(null, uniqueName);
// //     }
// // });

// // const handleMultipartData = multer({
// //     storage,
// //     limits: { fileSize: 1000000 * 1 },
// // }).single('image'); // 1mb

// const WaterLevelController = {

//     async waterLevel(req, res, next){
//         const {image, led_status, water_level} = req.body;
//         try {
//             const replace_2F = image.replace(/%2F/g, '/'); // %2F = /
//             const final_image = replace_2F.replace(/%2B/g, '+'); // %2B = +

//             console.log(final_image)

//             // const replace_2F = image.split("%2F").join("/"); // %2F = /
//             // const final_image = replace_2F.split("%2B").join("+"); // %2B = +
               
//             // const image_path = "uploads/";
//             // const image_name = `${Date.now()}_${Math.round(Math.random() * 1e9)}.png`;
//             // const image_name = "uploads/water.png";

//             // fs.writeFileSync('inputfile.txt', JSON.stringify([{image:'data:image/png;base64,'+final_image}]))
//             fs.writeFileSync('inputfile.txt', JSON.stringify({image:'data:image/png;base64,'+final_image}));

//             // fs.writeFileSync(image_path + image_name,final_image, {encoding: 'base64'}, function(err){
//             fs.writeFileSync("uploads/water.gif",final_image, {encoding: 'base64'}, function(err){
//                 console.log('File created');
//             });
                
//             return res.send('Water level status updated successfully');
//         } catch (err) {
//             return next(err);
//         }

//     },

//     async index(req, res, next){
//         const base64_string = fs.createReadStream('inputfile.txt','utf-8');
//         base64_string.pipe(res);
//     },

//     async getLedStatus(req, res, next){
//         let documents;
//         try {
//             documents = await WaterLevel.find().select('-createdAt -updatedAt -__v');
//         } catch (err) {
//             return next(CustomErrorHandler.serverError());
//         }
//         return res.json({status:200, data:documents});
//     },

//     async updateLedStatus(req, res, next){
//         let document;
//         try {
//             const {led_status} = req.body;
//             await WaterLevel.find().then(function([response]) {
//                 document = response;
//             });
//             if(document){
//                 await WaterLevel.findByIdAndUpdate(
//                 { _id: ObjectId(document._id)},
//                 {
//                     led_status:led_status,
//                     // water_level:water_level,
//                     // image:image_path + image_name,
//                     // image:image_name,
//                 },
//                 {new: true});
//                 return res.send(CustomSuccessHandler.success('Water updated successfully'));
//             }else{
//                 const waterLevel = new WaterLevel({
//                     led_status:led_status,
//                     // water_level:water_level,
//                     // image:image_path + image_name,
//                     // image:image_name,
//                 });
//                 const result = await waterLevel.save();
//                 return res.send(CustomSuccessHandler.success('Water level status updated successfully'));
//             }
            
//         } catch (err) {
//             return next(CustomErrorHandler.serverError());
//         }
//         // return res.json({status:200, data:document});
//     },

//     // async waterLevel(req, res, next){

        
//     //     // fs.writeFileSync(image_path + image_name,image, {encoding: 'base64'}, function(err){
//     //     //     console.log('File created');
//     //     // });

//     //     // res.send(CustomSuccessHandler.success('Led status updated successfully'));
//     //     // const destination = 'assets/images/water_level/uploads/'
//     //     // const filePath = req.file.path;

//     //     // fs.writeFile('image.png', base64Image, {encoding: 'base64'}, function(err) {
//     //     //     console.log('File created');
//     //     // });

//     //     // const bitmap = Buffer.from(req.body.image, 'base64');
//     //     // fs.writeFileSync("assets/images/water_level/uploads/example.png", bitmap);

        
//     //     // await decode(image, { fname: './assets/images/water_level/uploads/example2', ext: 'png' });
//     //     // await decode(image, { fname: 'assets/images/water_level/uploads/example2', ext: 'png' });
        
        
//     //     // fs.writeFileSync(fileName, data, {encoding: 'base64'}, function(err){
//     //     //     //Finished
//     //     // });
        

//     //     // save image
//     //     // handleMultipartData(req, res, async (err) => {
//     //     //     // if (err) {
//     //     //     //     return next(CustomErrorHandler.serverError(err.message));
//     //     //     // }
//     //     //     console.log(req)
//     //     //     // console.log(req.file)
//     //     //     const filePath = req.file.path;
//     //     //     // console.log(filePath)
//     //     //     //validation
//     //     //     const waterLevelSchema = Joi.object({
//     //     //         led_status:Joi.string().required()
//     //     //     })
//     //     //     const {error} = waterLevelSchema.validate(req.body);
//     //     //     if (error) {
//     //     //         //delete image

//     //     //         fs.unlink(`${appRoot}/${filePath}`, (err) => {
//     //     //             if (err) {
//     //     //                 return next(
//     //     //                     CustomErrorHandler.serverError(err.message)
//     //     //                 );
//     //     //             }
//     //     //         });
//     //     //         return next(error);
//     //     //         // rootfolder/uploads/filename.png
//     //     //     }

        
            
//     //         const {image, led_status, water_level} = req.body;
//     //         let document ;
//     //         try {

//     //             const replace_2F = image.replace(/%2F/g, '/'); // %2F = /
//     //             const final_image = replace_2F.replace(/%2B/g, '+'); // %2B = +

//     //             // console.log('final_image');
//     //             // console.log(final_image);

//     //             // const writeStream = fs.createWriteStream('inputfile.text');
//     //             // final_image.pipe(writeStream);

//     //             // fs.writeFileSync('inputfile.text', final_image);

//     //             // const replace_2F = image.split("%2F").join("/"); // %2F = /
//     //             // const final_image = replace_2F.split("%2B").join("+"); // %2B = +
               

//     //             const image_path = "uploads/";
//     //             // const image_name = `${Date.now()}_${Math.round(Math.random() * 1e9)}.png`;
//     //             const image_name = "uploads/water.png";

//     //             // fs.writeFileSync(image_path + image_name,final_image, {encoding: 'base64'}, function(err){
//     //             fs.writeFileSync(image_name,final_image, {encoding: 'base64'}, function(err){
//     //                 console.log('File created');
//     //             });
//     //             await WaterLevel.find().then(function([response]) {
//     //                 document = response;
//     //             });

//     //             if(document){
//     //                 await WaterLevel.findByIdAndUpdate(
//     //                 { _id: ObjectId(document._id)},
//     //                 {
//     //                     // led_status:led_status,
//     //                     // water_level:water_level,
//     //                     // image:image_path + image_name,
//     //                     image:image_name,
//     //                 },
//     //                 {new: true});
//     //                 res.send(CustomSuccessHandler.success('Water updated successfully'));
//     //             }else{
//     //                 const waterLevel = new WaterLevel({
//     //                     // led_status:led_status,
//     //                     // water_level:water_level,
//     //                     // image:image_path + image_name,
//     //                     image:image_name,
//     //                 });
//     //                 const result = await waterLevel.save();
//     //                 res.send(CustomSuccessHandler.success('Water level status updated successfully'));
//     //             }

//     //         } catch (err) {
//     //             return next(err);
//     //         }

//     //         // await decode(image, { fname: image_path + image_name, ext: 'png' });
 
//     //     // });
    
//     // },

//     // async index(req, res, next){
//     //     let documents;
//     //     // documents = fs.createReadStream('inputfile.text');
//     //     // // documents.pipe();
//     //     // console.log(documents)
//     //     try {

//     //         documents = await WaterLevel.find();

//     //         // await WaterLevel.find().then(function ([res]) {
//     //         //     documents = res;
//     //         // })
//     //     } catch (err) {
//     //         return next(CustomErrorHandler.serverError());
//     //     }
//     //     return res.json({status:200, data:documents});
//     // },

    
      
// }

// export default WaterLevelController;

