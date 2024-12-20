# Blue Giants

## Project Name
Blue Giants

## Project Description
**Blue Giants** is an educational platform designed to provide information about whales, the largest and most majestic creatures of the ocean. This project features a backend system that stores whale data in MongoDB and a frontend interface where users can explore and interact with this information.

**Purpose:**
The project aims to raise awareness about whales, their characteristics, and their importance in marine ecosystems.

**What It Does:**
- Allows users to add information about different whale species, such as their name and description.
- Displays a list of stored whales in an interactive and visually appealing table on the website.
- Provides a simple and intuitive interface to explore whale-related information.

**Target Audience:**
- Marine life enthusiasts and conservationists.
- Students and educators seeking resources on marine biology.
- Developers looking to understand full-stack development with Golang and MongoDB.

## Team Members
- Amir Zhunussov, Zhandarbek Zhetpissov, Ernar Aubakir

## Screenshot
![Blue Giants Preview](blue%20giants%20preview.png)



## Getting Started

### Prerequisites
1. **Golang:** Install Go (version 1.20 or higher). [Download here](https://go.dev/dl/).
2. **MongoDB:** Install MongoDB Community Edition or use MongoDB Atlas for cloud hosting. [Download here](https://www.mongodb.com/try/download/community).
3. **Postman:** For testing API endpoints. [Download here](https://www.postman.com/).

### Installation Steps

#### Backend Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/blue-giants.git
   cd blue-giants
   ```
2. Navigate to the backend folder:
   ```bash
   cd backend
   ```
3. Initialize Go modules (if not already done):
   ```bash
   go mod init blue_giants
   go mod tidy
   ```
4. Run the backend server:
   ```bash
   go run main.go
   ```
5. Ensure the server is running on port `8080`.

#### Frontend Setup
1. Navigate to the `frontend` folder:
   ```bash
   cd frontend
   ```
2. Open `index.html` in your preferred web browser.

### How to Use
1. Visit the homepage (`index.html`) to access the platform.
2. Use the form to add a whale by providing its name and description.
3. Click the "Fetch Whales" button to view all added whales in a table format.
4. Use Postman or curl to test backend API endpoints (`/add-whale` and `/get-whales`).

## Tools and Resources
- **Backend:** Golang
- **Database:** MongoDB (Compass for local testing, Atlas for cloud hosting)
- **Frontend:** HTML, CSS, JavaScript
- **API Testing:** Postman
- **Code Editor:** Visual Studio Code


Feel free to reach out if you have any questions or need support with the project.

