import { ProjectTeam } from "../../models/index.js";
import { projectTeamSchema } from "../../validators/index.js";
import CustomErrorHandler from "../../services/CustomErrorHandler.js";
import CustomSuccessHandler from "../../services/CustomSuccessHandler.js";
import { ObjectId } from "mongodb";

const projectTeamController = {

    async index(req, res, next){
        let documents;
       
        try {
            // documents = await ProjectTeam.find({project_id:req.params.id}).select('-createdAt -updatedAt -__v');

            documents =  await ProjectTeam.aggregate([
                {
                    $match: {
                        "project_id": ObjectId(req.params.id)
                    }
                },
                {
                    $lookup: {
                        from: 'projects',
                        localField: 'project_id',
                        foreignField: '_id',
                        as: 'project_data'
                    },
                },
                { $unwind: "$project_data" },
                {
                    $lookup: {
                        from: 'users',
                        localField: 'users.user_id',
                        foreignField: '_id',
                        as: 'user_arr'
                    },
                },
                {
                    $project: {
                            project_id:'$project_data._id',
                            project_name:'$project_data.project_name',
                            project_team: {
                            $map: {
                                input: '$user_arr',
                                as: 'users_data',
                                in: {
                                $mergeObjects: [
                                    {
                                        user_id: '$$users_data._id',
                                        user_name: '$$users_data.name',
                                    },
                                    // {$indexOfArray: ['$my_array.user_id', '$$users_data._id']},
                                ],
                            }
                        
                            }
                        }
                    }
            
                } 
                
            ])
          
            // documents =  await ProjectTeam.aggregate([
            //     {
            //         $match: {
            //             "project_id": ObjectId(req.params.id)
            //         }
            //     },
            //     {
            //         $lookup: {
            //             from: "projects",
            //             localField: "project_id",
            //             foreignField: "_id",
            //             as: 'data'
            //         }
            //     },
            //     {$unwind:"$data"}, 
            //     {
            //         $project: {
            //             _id: 1,
            //             project_id: 1,
            //             project_name:"$data.project_name",
            //         }
            //     } 
            // ])
            // .then(function ([res]) {
            //     user = res;
            // })

        } catch (err) {
            return next(CustomErrorHandler.serverError());
        }
        return res.json(documents);
    },

    async store(req, res, next){
        const {error} = projectTeamSchema.validate(req.body);
        if(error){
            return next(error);
        }

        const {project_id, user_id} = req.body;
        let project_exist_id
        project_exist_id = await ProjectTeam.findOne({ project_id:ObjectId(project_id) });

        if (!project_exist_id) {
            const project_team = new ProjectTeam({
                project_id
            });
            const result = await project_team.save();
            project_exist_id = result._id;
        }

        try {

            // user_id.forEach(element => {
                
            // });

            const document = await ProjectTeam.findByIdAndUpdate( 
                {_id: ObjectId(project_exist_id)},
                // { $push: {users: {user_id : user_id,} } }, // single code insert

                {
                    
                    $push: {
                        'users': {
                            $each:user_id.map((id) => {
                                return { user_id:id };
                            })
                        },
                    },

                    // $addToSet: {
                    //     users: {
                    //        $each: [ 
                    //         { user_id: ObjectId('62bc3d6fd368747a9fe3e99f') },
                    //         { user_id: ObjectId('62c2affaa77f4f2ce4a10b3e') },
                    //     ],
                    //     }
                    // }


                    // $addToSet: { 
                    //     users: {
                    //         $each: users
                    //     }
                    // } 
                },
                {new:true} 
            )
            res.send(CustomSuccessHandler.success('Project assign successfully'));
        } catch (err) {
            return next(err);
        } 

    },

}

export default projectTeamController;