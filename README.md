---
This is an old project and does not describe my products.
---
# My E-commerce API

## Description
This project is an e-commerce API designed to facilitate managing products, categories, and orders for an online store. It provides a robust and scalable backend solution for e-commerce applications.

## Features
- User Authentication: Secure sign-up, login, and logout functionalities.
- Product Management: Create, read, update, and delete products.
- Category Management: Organize products into categories.
- Order Management: Process and manage customer orders.
- Search and Filtering: Advanced search and filtering options for products.
- Pagination: Efficient handling of large datasets with pagination support.
- API Documentation: Comprehensive API documentation for developers.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/21Ravan12/My-ecomerse-Api.git
   ```
2. Navigate to the project directory:
   ```bash
   cd My-ecomerse-Api
   ```
3. Install the dependencies:
   ```bash
   npm install
   ```
4. Set up environment variables: Create a `.env` file and add the required environment variables such as database connection strings, JWT secrets, etc.
5. Run database migrations: Ensure your database is set up correctly by running necessary migrations.
   ```bash
   npm run migrate
   ```

## Usage
1. Start the server:
   ```bash
   npm start
   ```
2. Access the API: The API will be accessible at `http://localhost:3000`. Use tools like Postman or cURL to interact with the endpoints.

## API Endpoints
- Authentication:
  - `POST /auth/signup` - Create a new user account.
  - `POST /auth/login` - Authenticate a user and obtain a token.
- Products:
  - `GET /products` - Retrieve a list of products.
  - `POST /products` - Create a new product.
  - `GET /products/:id` - Retrieve a single product by ID.
  - `PUT /products/:id` - Update a product by ID.
  - `DELETE /products/:id` - Delete a product by ID.
- Categories:
  - `GET /categories` - Retrieve a list of categories.
  - `POST /categories` - Create a new category.
  - `GET /categories/:id` - Retrieve a single category by ID.
  - `PUT /categories/:id` - Update a category by ID.
  - `DELETE /categories/:id` - Delete a category by ID.
- Orders:
  - `GET /orders` - Retrieve a list of orders.
  - `POST /orders` - Create a new order.
  - `GET /orders/:id` - Retrieve a single order by ID.
  - `PUT /orders/:id` - Update an order by ID.
  - `DELETE /orders/:id` - Delete an order by ID.

## Database Structure

The `e-commerce-db` database consists of the following tables:

1. **campaigns**
   - `campaign_id`: Unique identifier for the campaign.
   - `campaign_name`: Name of the campaign.
   - `start_date`: Start date of the campaign.
   - `end_date`: End date of the campaign.
   - `status`: Current status of the campaign.
   - `valid_categories`: Categories where the campaign is applicable.
   - `created_at`: Creation date of the campaign.
   - `campaign_type`: Type of the campaign.
   - `campaign_amount`: Amount related to the campaign.
   - `usage_limit`: Limit on the usage of the campaign.

2. **categories**
   - `idcategories`: Unique identifier for the category.
   - `name`: Name of the category.
   - `description`: Description of the category.

3. **orders**
   - `idorders`: Unique identifier for the order.
   - `idcustomer`: Identifier for the customer who placed the order.
   - `order`: Details of the order.
   - `time`: Time when the order was placed.
    
4. **orders_completed**
   - `idorders_copmleted`: Unique identifier for the completed order.
   - `idcustomer`: Identifier for the customer who placed the order.
   - `order_details`: Detailed information about the order.
   - `order_time`: Time when the order was placed.
   - `copmletetion_time`: Time when the order was completed.
       
5. **payments**
   - `idpayments`: Unique identifier for the payment.
   - `orderid`: Identifier for the order related to the payment.
   - `customerid`: Identifier for the customer who made the payment.
   - `paymentstatus`: Status of the payment.
   - `paymentmethod`: Method used for the payment.
   - `totalamount`: Total amount of the payment.
   - `currency`: Currency of the payment.
   - `description`: Description of the payment.
   - `paymentdate`: Date when the payment was made.
      
6. **products**
   - `idproducts`: Unique identifier for the product.
   - `idseller`: Identifier for the seller of the product.
   - `category`: Category of the product.
   - `name`: Name of the product.
   - `price`: Price of the product.
   - `description`: Description of the product.
   - `quantity`: Quantity of the product available.
   - `comments`: Comments about the product.
        
7. **promotion_codes**
   - `idpromotion_codes`: Unique identifier for the promotion code.
   - `promotion_code`: The promotion code itself.
   - `state_date`: Start date of the promotion code.
   - `end_date`: End date of the promotion code.
   - `status`: Current status of the promotion code.
   - `usage_limit`: Limit on the usage of the promotion code.
   - `promotion_type`: Type of the promotion code.
   - `promotion_amount`: Amount related to the promotion code.
     
8. **return_requests**
   - `id`: Identifier for the request.
   - `idcustomer`: Identifier for the customer who made the return request.
   - `idorder`: Identifier for the order related to the return request.
   - `reason`: Reason for the return request.
   - `description`: Description of the return request.
   - `request_date`: Date when the return request was made.
   - `status`: Current status of the return request.
   - `completion_date`: Date when the return request was completed.

10. **users**
   - `id`: Unique identifier for the user.
   - `name`: Name of the user.
   - `email`: Email of the user.
   - `password`: Password of the user.
   - `birthyear`: Possibly the address or location of the user.
   - `usertier`: The tier or level of the user.
   - `cart`: Cart information associated with the user.

## Contributing
We welcome contributions to improve the project. Please follow these steps to contribute:
1. Fork the repository.
2. Create a new branch:
   ```bash
   git checkout -b feature-branch
   ```
3. Make your changes and commit them:
   ```bash
   git commit -m "Description of changes"
   ```
4. Push to the branch:
   ```bash
   git push origin feature-branch
   ```
5. Open a pull request: Provide a detailed description of the changes and any additional context.


## Contact
For any inquiries, please contact [21Ravan12](https://github.com/21Ravan12).

---
