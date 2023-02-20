export class Wiregasm {
  lib: any;
  initialized: boolean;
  session: any;
  uploadDir: string;

  constructor() {
    this.initialized = false;
    this.session = null;
  }

  async init(loader: any, overrides: object = {}) {
    if (this.initialized) {
      return;
    }
    this.initialized = true;

    this.lib = await loader(overrides);
    this.uploadDir = this.lib.getUploadDirectory();
    this.lib.init();
  }

  test_filter(filter: string): any {
    return this.lib.checkFilter(filter);
  }

  load(name: string, data: string | ArrayBufferView, opts: object = {}): any {
    if (this.session != null) {
      this.session.delete();
    }

    const path = this.uploadDir + "/" + name;
    this.lib.FS.writeFile(path, data, opts);

    this.session = new this.lib.DissectSession(path);

    return this.session.load();
  }

  frames(filter: string, skip = 0, limit = 0): any {
    return this.session.getFrames(filter, skip, limit);
  }

  frame(num: number): any {
    return this.session.getFrame(num);
  }

  destroy() {
    if (this.initialized) {
      if (this.session !== null) {
        this.session.delete();
        this.session = null;
      }

      this.lib.destroy();
      this.initialized = false;
    }
  }

  columns(): string[] {
    const vec = this.lib.getColumns();

    // convert it from a vector to array
    return new Array(vec.size()).fill(0).map((_, id) => vec.get(id));
  }
}
