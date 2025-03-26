package main

import (
	"fmt"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func main() {

	dsn := "cp_65011212189:65011212189@csmsu@tcp(202.28.34.197)/myadmin/sql.php?server=1&db=cp_65011212189&table=customer&pos=0"
	dialactor := mysql.Open(dsn)
	_, err := gorm.Open(dialactor)
	if err != nil {
		panic(err)
	}
	fmt.Println("Connection Successful")

}
