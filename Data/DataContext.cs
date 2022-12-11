using Microsoft.EntityFrameworkCore;

using signup_recover.Models;

namespace signup_recover.Data
{
  public class DataContext : DbContext
  {
    public DataContext(DbContextOptions<DataContext> options) : base(options) { }

    public DbSet<User> Users { get; set; }
  }
}