#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <archive.h>
#include <archive_entry.h>

static int copy_data(struct archive *ar, struct archive *aw) {
   const void *buffer;
   size_t size;
   la_int64_t offset;

   for (;;) {
      int reader = archive_read_data_block(ar, &buffer, &size, &offset);

      if (reader == ARCHIVE_EOF) {
         return (ARCHIVE_OK);
      }

      if (reader < ARCHIVE_WARN) {
         fprintf(stderr, "%s\n", archive_error_string(ar));
         return (reader);
      }

      reader = archive_write_data_block(aw, buffer, size, offset);

      if (reader < ARCHIVE_OK) {
         fprintf(stderr, "%s\n", archive_error_string(aw));
         return (reader);
      }
   }
}

void unzipfs(const char * path, const char * destination) {
   struct archive *tarball;
   struct archive *ext;
   struct archive_entry *entry;
   int flags;
   int reader;

   printf("Unpacking tarball %s\n", path);

   // go to the destination directory
   if (chdir(destination) != 0) {
      printf("Creating the destination directory\n");

      if (mkdir(destination, 0755) != 0) {
         perror("Error creating the destination directory");
         return;
      }

      if (chdir(destination) != 0) {
         perror("Cannot change directory to destination");
         return;
      }
   }

   mode_t old_umask = umask(0);

   // select attributes to unzip
   flags = ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL | ARCHIVE_EXTRACT_FFLAGS | ARCHIVE_EXTRACT_SECURE_NODOTDOT | ARCHIVE_EXTRACT_OWNER | ARCHIVE_EXTRACT_UNLINK | ARCHIVE_EXTRACT_XATTR;

   // setup tarball
   tarball = archive_read_new();
   archive_read_support_format_all(tarball);
   archive_read_support_filter_all(tarball);

   // setup disk write
   ext = archive_write_disk_new();
   archive_write_disk_set_options(ext, flags);
   archive_write_disk_set_standard_lookup(ext);

   if ((reader = archive_read_open_filename(tarball, path, 10240)) != ARCHIVE_OK) {
      fprintf(stderr, "%s\n", archive_error_string(tarball));

      archive_read_free(tarball);
      archive_write_free(ext);
      umask(old_umask);
      return;
   }

   int r;
   while ((r = archive_read_next_header(tarball, &entry)) != ARCHIVE_EOF) {
      if (r < ARCHIVE_OK) {
         fprintf(stderr, "%s\n", archive_error_string(tarball));

         if (r < ARCHIVE_WARN) {
            break;
         }
      }

      const char *current_path = archive_entry_pathname(entry);
      if (current_path[0] == '/') {
         archive_entry_set_pathname(entry, current_path + 1);
      }

      reader = archive_write_header(ext, entry);

      if (reader == ARCHIVE_WARN) {
         fprintf(stderr, "%s\n", archive_error_string(ext));
      }

      if (reader < ARCHIVE_OK) {
         fprintf(stderr, "%s\n", archive_error_string(ext));
      } else {
         reader = copy_data(tarball, ext);

         if (reader < ARCHIVE_OK) {
            fprintf(stderr, "%s\n", archive_error_string(ext));
         }
      }

      reader = archive_write_finish_entry(ext);

      if (reader < ARCHIVE_OK) {
         fprintf(stderr, "%s\n", archive_error_string(ext));
      }
   }

   archive_read_close(tarball);
   archive_read_free(tarball);
   archive_write_close(ext);
   archive_write_free(ext);

   umask(old_umask);
   sync();
   printf("Filesystem unzipped\n");
}