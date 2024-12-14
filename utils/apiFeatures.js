class APIFeatures {
    constructor(query, queryString) {
      this.query = query;
      this.queryString = queryString;
    }
  
    filter() {
      // Basic filtering (excluding special query fields)
      const queryObj = { ...this.queryString };
      const excludedFields = ['page', 'sort', 'limit', 'fields'];
      excludedFields.forEach(el => delete queryObj[el]);
  
      // Advanced filtering (e.g., gte, gt, lte, lt)
      let queryStr = JSON.stringify(queryObj);
      queryStr = queryStr.replace(/\b(gte|gt|lte|lt|eq|ne)\b/g, match => `$${match}`);
  
      this.query = this.query.find(JSON.parse(queryStr));
  
      return this;
    }
  
    sort() {
      // Sort by fields (e.g., ?sort=name,email or default by createdAt descending)
      if (this.queryString.sort) {
        const sortBy = this.queryString.sort.split(',').join(' ');
        this.query = this.query.sort(sortBy);
      } else {
        this.query = this.query.sort('-createdAt'); // Default sort
      }
  
      return this;
    }
  
    limitFields() {
      // Select specific fields (e.g., ?fields=name,email)
      if (this.queryString.fields) {
        const fields = this.queryString.fields.split(',').join(' ');
        this.query = this.query.select(fields);
      } else {
        this.query = this.query.select('-__v'); // Exclude Mongoose internal field by default
      }
  
      return this;
    }
  
    paginate() {
      // Pagination logic (e.g., ?page=2&limit=10)
      const page = this.queryString.page * 1 || 1;
      const limit = this.queryString.limit * 1 || 10; // Default limit: 10
      const skip = (page - 1) * limit;
  
      this.query = this.query.skip(skip).limit(limit);
  
      return this;
    }
  
    filterPermissions() {
      // Filtering by user permissions (e.g., ?permissions[email]=true)
      if (this.queryString.permissions) {
        const permissions = JSON.parse(this.queryString.permissions);
        this.query = this.query.find({ permissions });
      }
  
      return this;
    }
  }
  
  module.exports = APIFeatures;
  