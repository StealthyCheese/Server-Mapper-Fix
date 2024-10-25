# Server-Mapper-Fix
take into consideration this example assumes
the target module has no extra protections besides iat + PE server mapped

Below is what this example looks like under IDA
 ![IDA](/WriteUp/imgs/IDA.png)

As you can see the entry refrences function addresses which are out of module.

To start fixing this we would need to get the imports called
