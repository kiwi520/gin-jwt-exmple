package main

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"jwt-todo/middlware"
	"jwt-todo/tools"
	"log"
	"net/http"
	"time"
)

var (
	router = gin.Default()
)

type Todo struct {
	UserID uint64 `json:"user_id"`
	Title  string `json:"title"`
	Content  string `json:"content"`
}


func main() {

	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:8081"},
		AllowMethods:     []string{"PUT", "PATCH","OPTIONS", "GET", "HEAD", "POST"},
		AllowHeaders:     []string{"Origin","X-PINGOTHER","Content-Type","Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		AllowOriginFunc: func(origin string) bool {
			return origin == "https://github.com"
		},
		MaxAge: 12 * time.Hour,
	})) //开启中间件 允许使用跨域请求
	api := router.Group("api")
	{
		api.POST("/login", tools.Login)
		api.POST("/token/refresh", tools.Refresh)
		api.POST("/todo", middlware.TokenAuthMiddleware(), CreateTodo)
		api.GET("/todolist", middlware.TokenAuthMiddleware(),TodoList)
		api.POST("/logout", middlware.TokenAuthMiddleware(), tools.Logout)
	}

	log.Fatal(router.Run(":8080"))
}

var todoList []*Todo

//创建todo
func CreateTodo(c *gin.Context) {
	var td *Todo
	if err := c.ShouldBindJSON(&td); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "invalid json")
		return
	}
	tokenAuth, err := tools.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	userId, err := tools.FetchAuth(tokenAuth)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	td.UserID = userId

	todoList = append(todoList,td)
	//you can proceed to save the Todo to a database
	//but we will just return it to the caller here:
	c.JSON(http.StatusCreated, todoList)
}

func TodoList(c *gin.Context)  {
	c.JSON(http.StatusOK, todoList)
}
