package controllers

import (
	"context"
	"fmt"
	"full-jwt/database"
	"full-jwt/helpers"
	"full-jwt/models"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2/bson"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var validate = validator.New()

func HashPassword(pwd string) string {
	hashedPwd, err := bcrypt.GenerateFromPassword([]byte(pwd), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(hashedPwd)
}

func VerifyPassword(userPwd string, providedPwd string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPwd), []byte(userPwd))
	check := true
	msg := ""
	if err != nil {
		msg = "email or password incorrect"
		check = false
	}

	return check, msg
}

func Signup() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var user models.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		validationErr := validate.Struct(user)

		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
			return
		}

		count, err := userCollection.CountDocuments(ctx, bson.M{
			"$or": []bson.M{
				{"email": user.Email},
				{"phone": user.Phone},
			},
		})

		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for email"})
			return
		}

		if count > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Email or Phone number already exists"})
		}

		user.Created_at = time.Now()
		user.Updated_at = time.Now()
		user.ID = primitive.NewObjectID()
		user.User_id = user.ID.Hex()
		token, refreshToken, _ := helpers.GenerateAllTokens(*user.Email, *user.First_name, *user.Last_name, *&user.User_id, *user.User_type)
		user.Token = &token
		user.Refresh_token = &refreshToken

		resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			msg := fmt.Sprintf("User item was not created")
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		c.JSON(http.StatusOK, resultInsertionNumber)
	}

}

func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var user models.User
		var foundUser models.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "email or password incorrect"})
			return
		}
		pwd := HashPassword(*user.Password)
		*&user.Password = pwd
		passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)

		if !passwordIsValid {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}
		if foundUser.Email == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "User not found"})
		}
		token, refreshToken, _ := helpers.GenerateAllTokens(*foundUser.Email, *foundUser.First_name, *foundUser.Last_name, *&foundUser.User_id, *foundUser.User_type)
		helpers.UpdateAllTokens(token, refreshToken, foundUser.User_id)
		err = userCollection.FindOne(ctx, bson.M{"user_id": foundUser.User_id}).Decode(&foundUser)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, foundUser)
	}
}

func GetUsers() gin.HandlerFunc{
	return func (c *gin.Context){
		if err:=helpers.CheckUserType(c, "ADMIN"); err!=nil{
			c.JSON(http.StatusBadRequest, gin.H{"error":err})
			return
		}
		ctx,cancel:=context.WithTimeout(context.Background(),100*time.Second)
		defer cancel()

		recordPerPage,err:=strconv.Atoi(c.Query("recordPerPage"))
		if err!=nil || recordPerPage <1{
			recordPerPage=10
		}

		page, err1:=strconv.Atoi(c.Query("page"))
		if err1!=nil || page <1{
			page=1
		}

		startIndex:=(page-1) * recordPerPage
		startIndex,err= strconv.Atoi(c.Query("startIndex"))

		matchStage:= bson.D{{"$match",bson.D{{}}}}

		grouptage:= bson.D{{"$group",bson.D{
			{"_id",bson.D{{"_id","null"}}},
			{"total_count",bson.D{{"$sum",1}}}, 
			{"data",bson.D{{"$push","$$ROOT"}}}
		}}}

		projectStage := bson.D{
			{"$project", bson.D{
				{"_id",0},
				{"total_count", 1},
				{"user_items", bson.D{{"$slice", []interface{}{"$data",startIndex,recordPerPage}}}},
			}}
		}

		result,err:=userCollection.Aggregate(ctx,mongo.Pipeline{
			matchStage, grouptage, projectStage
		})

		if err!=nil{
			c.JSON(http.StatusInternalServerError, gin.H{"error":"error occured while listing users"})
		}

		var allUsers []bson.M
		if err =result.All(ctx,&allUsers); err!=nil{
			log.Fatal(err)
		}

		c.JSON(http.StatusOK, allUsers[0])
	}
}

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Param("user_id")

		if err := helpers.MatchUserTypeToUid(c, userId); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error})
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		var user models.User

		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, user)
	}
}
